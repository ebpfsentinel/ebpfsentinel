/*
 * bench-shaper.bpf.c - a BPF qdisc that shapes each cgroup to a rate by
 * itself, built only for perf/09 to compare against the tc-qos departure
 * time served by fq. It is not part of the agent: no crate loads it, no
 * release carries it, and the suite registers it, measures and unregisters it.
 *
 * What it does, packet by packet:
 *   enqueue  reads the cgroup of the socket that sent the packet, looks the
 *            cgroup up in `bench_classes`, and gives the packet a departure
 *            time from that cgroup's own clock, with the same arithmetic as
 *            tc-qos (picoseconds per byte, and a horizon beyond which the
 *            packet is dropped instead). A packet of no listed cgroup leaves
 *            at once, or at the departure time its sender already wrote.
 *            Every packet then sits in one tree ordered by departure time.
 *   dequeue  hands out the first packet of the tree once its time has come,
 *            and otherwise arms the qdisc watchdog for that time.
 *
 * The qdisc's operations run under the root lock of the qdisc, so the clock
 * of a cgroup is read and moved by one CPU at a time. The tree still takes a
 * bpf_spin_lock, which the verifier requires around every graph operation.
 *
 * The harness writes one entry per cgroup before traffic starts:
 *   key    the cgroup id (the inode number of its directory under
 *          /sys/fs/cgroup), 8 bytes little-endian
 *   value  struct bench_class, 48 bytes little-endian, the first two fields
 *          set and the other four zero
 * and reads the counters back from the same map.
 *
 * Built by build.sh beside it, on the machine that loads it, against that
 * kernel's BTF: it uses kfuncs (bpf_obj_new, the rbtree, the qdisc kfuncs)
 * and declares the GPL licence the kernel requires of a struct_ops program.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "bpf_qdisc_common.h"

char _license[] SEC("license") = "GPL";

/* Packets the qdisc holds before it drops at enqueue. */
#define BENCH_LIMIT 10000
/* How far ahead a departure time the sender wrote is honoured. */
#define BENCH_SENDER_HORIZON_NS (10ULL * 1000 * 1000 * 1000)
/* Slack given to the watchdog, as sch_fq's default timer slack. */
#define BENCH_TIMER_SLACK_NS (10ULL * 1000)

/* Socket states that are not a full socket, whose cgroup is not read. */
#define BENCH_SK_TIME_WAIT 6
#define BENCH_SK_NEW_SYN_RECV 12

struct bench_class {
	__u64 ps_per_byte;
	__u64 horizon_ns;
	__u64 next_departure;
	__u64 bytes;
	__u64 packets;
	__u64 dropped_horizon;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct bench_class);
} bench_classes SEC(".maps");

struct skb_node {
	__u64 departure;
	struct sk_buff __kptr *skb;
	struct bpf_rb_node node;
};

private(A) struct bpf_spin_lock bench_lock;
private(A) struct bpf_rb_root bench_queue __contains(skb_node, node);

static bool departure_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct skb_node *node_a = container_of(a, struct skb_node, node);
	struct skb_node *node_b = container_of(b, struct skb_node, node);

	return node_a->departure < node_b->departure;
}

/* Nanoseconds len bytes occupy at ps_per_byte, as tc-qos computes them. */
static __u64 spacing_ns(__u32 len, __u64 ps_per_byte)
{
	__u64 whole = ps_per_byte / 1000;
	__u64 rest = ps_per_byte % 1000;

	if (whole > 0xffffffffULL)
		whole = 0xffffffffULL;
	return (__u64)len * whole + (__u64)len * rest / 1000;
}

/* The cgroup v2 id of the full socket that sent skb, or 0. */
static __u64 sender_cgroup_id(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct cgroup *cgrp;
	unsigned char state;

	if (!sk)
		return 0;
	state = sk->__sk_common.skc_state;
	if (state == BENCH_SK_TIME_WAIT || state == BENCH_SK_NEW_SYN_RECV)
		return 0;
	cgrp = sk->sk_cgrp_data.cgroup;
	if (!cgrp || !cgrp->kn)
		return 0;
	return cgrp->kn->id;
}

SEC("struct_ops/bench_shaper_enqueue")
int BPF_PROG(bench_shaper_enqueue, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	struct bench_class *class = NULL;
	struct skb_node *skbn;
	__u64 now, departure, sender_time, cgroup_id;
	__u32 len;

	if (sch->q.qlen >= sch->limit)
		goto drop;

	now = bpf_ktime_get_ns();
	len = qdisc_pkt_len(skb);
	departure = now;
	sender_time = skb->tstamp;
	if (sender_time > now && sender_time - now <= BENCH_SENDER_HORIZON_NS)
		departure = sender_time;

	cgroup_id = sender_cgroup_id(skb);
	if (cgroup_id)
		class = bpf_map_lookup_elem(&bench_classes, &cgroup_id);
	if (class) {
		if (class->next_departure > departure)
			departure = class->next_departure;
		if (departure - now > class->horizon_ns) {
			class->dropped_horizon += 1;
			goto drop;
		}
		class->next_departure = departure + spacing_ns(len, class->ps_per_byte);
		class->bytes += len;
		class->packets += 1;
	}

	skbn = bpf_obj_new(typeof(*skbn));
	if (!skbn)
		goto drop;
	skbn->departure = departure;

	sch->q.qlen++;
	skb = bpf_kptr_xchg(&skbn->skb, skb);
	if (skb)
		bpf_qdisc_skb_drop(skb, to_free);

	bpf_spin_lock(&bench_lock);
	bpf_rbtree_add(&bench_queue, &skbn->node, departure_less);
	bpf_spin_unlock(&bench_lock);

	sch->qstats.backlog += len;
	return NET_XMIT_SUCCESS;
drop:
	bpf_qdisc_skb_drop(skb, to_free);
	return NET_XMIT_DROP;
}

SEC("struct_ops/bench_shaper_dequeue")
struct sk_buff *BPF_PROG(bench_shaper_dequeue, struct Qdisc *sch)
{
	struct bpf_rb_node *rb_node;
	struct skb_node *skbn;
	struct sk_buff *skb = NULL;
	__u64 now, departure;

	if (!sch->q.qlen)
		return NULL;

	now = bpf_ktime_get_ns();
	bpf_spin_lock(&bench_lock);
	rb_node = bpf_rbtree_first(&bench_queue);
	if (!rb_node) {
		bpf_spin_unlock(&bench_lock);
		return NULL;
	}
	skbn = container_of(rb_node, struct skb_node, node);
	departure = skbn->departure;
	if (departure > now) {
		bpf_spin_unlock(&bench_lock);
		bpf_qdisc_watchdog_schedule(sch, departure, BENCH_TIMER_SLACK_NS);
		return NULL;
	}
	rb_node = bpf_rbtree_remove(&bench_queue, rb_node);
	bpf_spin_unlock(&bench_lock);
	if (!rb_node)
		return NULL;

	skbn = container_of(rb_node, struct skb_node, node);
	skb = bpf_kptr_xchg(&skbn->skb, skb);
	bpf_obj_drop(skbn);
	if (!skb)
		return NULL;

	sch->q.qlen--;
	sch->qstats.backlog -= qdisc_pkt_len(skb);
	bpf_qdisc_bstats_update(sch, skb);
	return skb;
}

SEC("struct_ops/bench_shaper_init")
int BPF_PROG(bench_shaper_init, struct Qdisc *sch, struct nlattr *opt,
	     struct netlink_ext_ack *extack)
{
	sch->limit = BENCH_LIMIT;
	return 0;
}

SEC("struct_ops/bench_shaper_reset")
void BPF_PROG(bench_shaper_reset, struct Qdisc *sch)
{
	struct bpf_rb_node *rb_node;
	struct skb_node *skbn;
	int i;

	bpf_for(i, 0, sch->q.qlen) {
		struct sk_buff *skb = NULL;

		bpf_spin_lock(&bench_lock);
		rb_node = bpf_rbtree_first(&bench_queue);
		if (!rb_node) {
			bpf_spin_unlock(&bench_lock);
			break;
		}
		rb_node = bpf_rbtree_remove(&bench_queue, rb_node);
		bpf_spin_unlock(&bench_lock);
		if (!rb_node)
			break;

		skbn = container_of(rb_node, struct skb_node, node);
		skb = bpf_kptr_xchg(&skbn->skb, skb);
		if (skb)
			bpf_kfree_skb(skb);
		bpf_obj_drop(skbn);
	}
	sch->q.qlen = 0;
	sch->qstats.backlog = 0;
}

SEC("struct_ops")
void BPF_PROG(bench_shaper_destroy, struct Qdisc *sch)
{
}

SEC(".struct_ops")
struct Qdisc_ops bench_shaper = {
	.enqueue = (void *)bench_shaper_enqueue,
	.dequeue = (void *)bench_shaper_dequeue,
	.init = (void *)bench_shaper_init,
	.reset = (void *)bench_shaper_reset,
	.destroy = (void *)bench_shaper_destroy,
	.id = "bench_shaper",
};
