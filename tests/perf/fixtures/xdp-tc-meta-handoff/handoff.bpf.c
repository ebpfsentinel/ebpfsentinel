/*
 * handoff.bpf.c - the parse handoff from XDP to the tc ingress chain, written
 * four ways so that perf/13 can set them side by side on the same traffic. It
 * is not part of the agent: no crate loads it, no release carries it, and the
 * suite loads it, measures and detaches it.
 *
 * The parse is the product's (crates/ebpf-helpers/src/pktmeta.rs): Ethernet,
 * up to two VLAN tags (802.1Q or 802.1ad), IPv4 by its IHL or IPv6 through up
 * to six extension headers with the same length rules and the same 512-byte
 * cap, then the TCP or UDP ports. The control block words are packed and
 * checked exactly as pktmeta packs them (magic byte, VLAN, flags, protocol,
 * offsets, ports, tenant, a check word folded over the four words, the
 * length and both interface indexes), and a write is skipped for a traced
 * packet as the product skips it. What this file adds is the metadata record
 * XDP leaves in front of the packet, which is the thing under test.
 *
 * Programs (names are what bpftool and kernel.bpf_stats report):
 *
 *   hm_xdp_parse   XDP parses the packet and uses the result, as the XDP
 *                  firewall does today, and leaves nothing behind.
 *   hm_xdp_meta    the same parse, then bpf_xdp_adjust_meta and the parse
 *                  written as five words in front of the packet: the four
 *                  control block words and a check word folded over them and
 *                  the receiving interface. Not the length: GRO merges
 *                  segments under the first one's metadata and the stack
 *                  takes a VLAN tag out, so the length TC sees is not the one
 *                  XDP saw.
 *   hm_tc_cb       today's pktmeta::resolve: the control block if a program
 *                  ahead in the chain left a valid one, else parse and leave
 *                  it there.
 *   hm_tc_dyn      resolve with one step in front of the parse: the metadata
 *                  read through bpf_dynptr_from_skb_meta and bpf_dynptr_slice,
 *                  copied into the control block for the programs behind.
 *   hm_tc_dyn_all  every program reads the metadata through the dynptr, the
 *                  control block used only when the metadata is not there.
 *   hm_tc_dmeta    as hm_tc_dyn, the metadata read through the direct
 *                  __sk_buff data_meta pointer instead of the dynptr.
 *   hm_tc_probe    not timed: reads the metadata both ways, parses the packet
 *                  as TC sees it and counts whether they agree, and what the
 *                  stack did with a VLAN tag (map hm_probe).
 *
 * Every timed program does one map lookup per run and one counter increment
 * per path it takes, so the counters cost every arm the same. The parse is
 * folded into a per-CPU sink, which keeps the compiler from dropping it.
 *
 * Built by build.sh beside it against the running kernel's BTF. GPL because
 * the kfuncs it calls are.
 */

#include "vmlinux.h"
#include "helpers.h"

char _license[] SEC("license") = "GPL";

#define HM_TCX_NEXT (-1)

#define ETH_HLEN 14
#define VLAN_HLEN 4
#define IPV4_HLEN 20
#define IPV6_HLEN 40
#define ET_IPV4 0x0800
#define ET_IPV6 0x86DD
#define ET_8021Q 0x8100
#define ET_8021AD 0x88A8
#define P_TCP 6
#define P_UDP 17
#define VLAN_MAX_TAGS 2
#define IPV6_EXT_MAX_HEADERS 6
#define IPV6_EXT_MAX_OFFSET 512

/* pktmeta's flags and word layout, same values. */
#define FLAG_IPV6 0x01
#define FLAG_VLAN 0x02
#define FLAG_IPV4 0x04
#define FLAG_TENANT 0x08
#define FLAG_MASK (FLAG_IPV6 | FLAG_VLAN | FLAG_IPV4 | FLAG_TENANT)
#define OFFSET_MASK 0x07FF
#define MAGIC 0xEBu
#define CHECK_SALT 0x5EB0F5E1u
#define TC_TRACE_MARK 0x54524345u
#define TC_TRACE_PRIORITY 0xEB5E0001u

/* The metadata record: four words and a check word. */
#define META_SALT 0x5EB0A11Du
#define META_LEN 20

struct meta {
	__u16 l3_off;
	__u16 l4_off;
	__u8 proto;
	__u8 flags;
	__u16 vlan_id;
	__u16 src_port;
	__u16 dst_port;
	__u32 tenant_id;
};

/* Per-CPU counters of the timed programs. */
enum {
	C_XDP_RUN,
	C_XDP_META_REFUSED,
	C_XDP_UNPARSED,
	C_XDP_VLAN_INLINE,
	C_TC_CB_HIT,
	C_TC_META_HIT,
	C_TC_META_BAD,
	C_TC_PARSE,
	C_TC_UNPARSED,
	C_MAX = 12,
};

struct counters {
	__u64 c[C_MAX];
	__u64 sink;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct counters);
} hm_cnt SEC(".maps");

/* What the probe saw, shared across CPUs. */
enum {
	P_RUNS,
	P_DYNPTR_VALID,
	P_DATAMETA_VALID,
	P_META_ABSENT,
	P_META_BAD,
	P_IP,
	P_AGREE,
	P_DISAGREE,
	P_AGREE_AFTER_STRIP,
	P_SKB_VLAN,
	P_META_VLAN,
	P_TC_INLINE_VLAN,
	P_VLAN_ID_AGREE,
	P_READERS_DIFFER,
	P_MAX = 16,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, P_MAX);
	__type(key, __u32);
	__type(value, __u64);
} hm_probe SEC(".maps");

static __hm_inline struct counters *counters(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&hm_cnt, &zero);
}

static __hm_inline void pcount(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&hm_probe, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

static __hm_inline __u16 be16(const __u8 *b)
{
	return ((__u16)b[0] << 8) | b[1];
}

static __hm_inline __u32 rotl(__u32 v, int s)
{
	return (v << s) | (v >> (32 - s));
}

static __hm_inline int is_ipv6_ext(__u8 p)
{
	return p == 0 || p == 43 || p == 44 || p == 51 || p == 60 || p == 135;
}

static __hm_inline __u32 ipv6_ext_len(__u8 type, __u8 len)
{
	if (type == 44)
		return 8;
	if (type == 51)
		return ((__u32)len + 2) * 4;
	return ((__u32)len + 1) * 8;
}

/* pktmeta::parse, on whichever packet window the hook hands over. */
static __hm_inline int parse(void *data, void *data_end, struct meta *m)
{
	__u16 et;
	__u32 l3 = ETH_HLEN, l4;
	int tagged = 0;

	__builtin_memset(m, 0, sizeof(*m));
	if (data + ETH_HLEN > data_end)
		return -1;
	et = be16((__u8 *)data + 12);

#pragma unroll
	for (int i = 0; i < VLAN_MAX_TAGS; i++) {
		__u8 *tag;

		if (et != ET_8021Q && et != ET_8021AD)
			break;
		tag = (__u8 *)data + l3;
		if ((void *)(tag + VLAN_HLEN) > data_end)
			return -1;
		if (!tagged) {
			m->vlan_id = be16(tag) & 0x0FFF;
			tagged = 1;
		}
		et = be16(tag + 2);
		l3 += VLAN_HLEN;
	}
	if (tagged)
		m->flags |= FLAG_VLAN;
	m->l3_off = l3;

	if (et == ET_IPV4) {
		__u8 *vihl = (__u8 *)data + l3;
		__u8 *proto = (__u8 *)data + l3 + 9;
		__u32 ihl;

		if ((void *)(vihl + 1) > data_end)
			return -1;
		if ((void *)(proto + 1) > data_end)
			return -1;
		ihl = (__u32)(*vihl & 0x0F) << 2;
		if (ihl < IPV4_HLEN)
			return -1;
		m->flags |= FLAG_IPV4;
		m->proto = *proto;
		l4 = l3 + ihl;
	} else if (et == ET_IPV6) {
		__u8 *nh = (__u8 *)data + l3 + 6;
		__u8 *pos;
		__u8 next;
		__u64 off;

		if ((void *)(nh + 1) > data_end)
			return -1;
		next = *nh;
		pos = (__u8 *)data + l3 + IPV6_HLEN;
#pragma unroll
		for (int i = 0; i < IPV6_EXT_MAX_HEADERS; i++) {
			__u8 this_hdr;

			if (!is_ipv6_ext(next))
				break;
			if ((void *)(pos + 2) > data_end)
				return -1;
			this_hdr = next;
			next = pos[0];
			pos += ipv6_ext_len(this_hdr, pos[1]);
			if ((void *)pos > data_end)
				return -1;
		}
		off = (__u64)((void *)pos - data);
		if (off > IPV6_EXT_MAX_OFFSET)
			return -1;
		m->flags |= FLAG_IPV6;
		m->proto = next;
		l4 = (__u32)off;
	} else {
		return 0;
	}
	m->l4_off = l4;

	if (m->proto == P_TCP || m->proto == P_UDP) {
		__u8 *ports = (__u8 *)data + l4;

		if ((void *)(ports + 4) <= data_end) {
			m->src_port = be16(ports);
			m->dst_port = be16(ports + 2);
		}
	}
	return 0;
}

static __hm_inline int parse_skb(struct __sk_buff *skb, struct meta *m)
{
	return parse((void *)(long)skb->data, (void *)(long)skb->data_end, m);
}

static __hm_inline void pack(const struct meta *m, __u32 w[4])
{
	w[0] = (MAGIC << 24) | ((__u32)(m->vlan_id & 0x0FFF) << 12) |
	       ((__u32)(m->flags & FLAG_MASK) << 8) | m->proto;
	w[1] = ((__u32)m->l3_off << 16) | m->l4_off;
	w[2] = ((__u32)m->src_port << 16) | m->dst_port;
	w[3] = m->tenant_id;
}

static __hm_inline void unpack(const __u32 w[4], struct meta *m)
{
	m->l3_off = (w[1] >> 16) & OFFSET_MASK;
	m->l4_off = w[1] & OFFSET_MASK;
	m->proto = w[0] & 0xFF;
	m->flags = ((w[0] >> 8) & 0xFF) & FLAG_MASK;
	m->vlan_id = (w[0] >> 12) & 0x0FFF;
	m->src_port = w[2] >> 16;
	m->dst_port = w[2] & 0xFFFF;
	m->tenant_id = w[3];
}

static __hm_inline int traced(struct __sk_buff *skb)
{
	return skb->mark == TC_TRACE_MARK && skb->priority == TC_TRACE_PRIORITY;
}

static __hm_inline __u32 cb_check(struct __sk_buff *skb, const __u32 w[4])
{
	return w[0] ^ w[1] ^ w[2] ^ w[3] ^ skb->len ^ rotl(skb->ifindex, 8) ^
	       rotl(skb->ingress_ifindex, 16) ^ CHECK_SALT;
}

static __hm_inline __u32 meta_check(const __u32 w[4], __u32 ifindex)
{
	return w[0] ^ w[1] ^ w[2] ^ w[3] ^ rotl(ifindex, 8) ^ META_SALT;
}

/* pktmeta::read_cb */
static __hm_inline int read_cb(struct __sk_buff *skb, struct meta *m)
{
	__u32 w[4] = { skb->cb[0], skb->cb[1], skb->cb[2], skb->cb[3] };
	__u32 check = skb->cb[4];

	if (w[0] >> 24 != MAGIC)
		return 0;
	if (check != cb_check(skb, w))
		return 0;
	unpack(w, m);
	return 1;
}

/* pktmeta::write_cb */
static __hm_inline void write_cb(struct __sk_buff *skb, const struct meta *m)
{
	__u32 w[4];
	__u32 check;

	if (traced(skb))
		return;
	pack(m, w);
	check = cb_check(skb, w);
	skb->cb[0] = w[0];
	skb->cb[1] = w[1];
	skb->cb[2] = w[2];
	skb->cb[3] = w[3];
	skb->cb[4] = check;
}

/* A metadata record: 1 valid, 0 not there, -1 there but not ours. */
static __hm_inline int meta_words(const __u32 *rec, __u32 ifindex, struct meta *m)
{
	__u32 w[4] = { rec[0], rec[1], rec[2], rec[3] };

	if (w[0] >> 24 != MAGIC)
		return -1;
	if (rec[4] != meta_check(w, ifindex))
		return -1;
	unpack(w, m);
	return 1;
}

static __hm_inline int read_meta_dynptr(struct __sk_buff *skb, struct meta *m)
{
	struct bpf_dynptr dp;
	__u32 buf[META_LEN / 4];
	__u32 *rec;

	if (bpf_dynptr_from_skb_meta(skb, 0, &dp))
		return 0;
	rec = bpf_dynptr_slice(&dp, 0, buf, sizeof(buf));
	if (!rec)
		return 0;
	return meta_words(rec, skb->ingress_ifindex, m);
}

static __hm_inline int read_meta_direct(struct __sk_buff *skb, struct meta *m)
{
	void *meta = (void *)(long)skb->data_meta;
	void *data = (void *)(long)skb->data;

	if (meta + META_LEN > data)
		return 0;
	return meta_words(meta, skb->ingress_ifindex, m);
}

static __hm_inline void use(struct counters *c, const struct meta *m)
{
	c->sink += (__u64)(m->src_port ^ m->dst_port ^ m->l4_off ^ m->proto ^ m->flags);
}

/* XDP: what runs today, the parse used and nothing left behind. */
SEC("xdp")
int hm_xdp_parse(struct xdp_md *ctx)
{
	struct counters *c = counters();
	struct meta m;

	if (!c)
		return XDP_PASS;
	c->c[C_XDP_RUN]++;
	if (parse((void *)(long)ctx->data, (void *)(long)ctx->data_end, &m)) {
		c->c[C_XDP_UNPARSED]++;
		return XDP_PASS;
	}
	if (m.flags & FLAG_VLAN)
		c->c[C_XDP_VLAN_INLINE]++;
	use(c, &m);
	return XDP_PASS;
}

/* XDP: the same, then the parse written in front of the packet. */
SEC("xdp")
int hm_xdp_meta(struct xdp_md *ctx)
{
	struct counters *c = counters();
	struct meta m;
	__u32 w[4];
	__u32 *rec;
	void *data;

	if (!c)
		return XDP_PASS;
	c->c[C_XDP_RUN]++;
	if (parse((void *)(long)ctx->data, (void *)(long)ctx->data_end, &m)) {
		c->c[C_XDP_UNPARSED]++;
		return XDP_PASS;
	}
	if (m.flags & FLAG_VLAN)
		c->c[C_XDP_VLAN_INLINE]++;
	use(c, &m);

	if (bpf_xdp_adjust_meta(ctx, -META_LEN)) {
		c->c[C_XDP_META_REFUSED]++;
		return XDP_PASS;
	}
	rec = (void *)(long)ctx->data_meta;
	data = (void *)(long)ctx->data;
	if ((void *)rec + META_LEN > data) {
		c->c[C_XDP_META_REFUSED]++;
		return XDP_PASS;
	}
	pack(&m, w);
	rec[0] = w[0];
	rec[1] = w[1];
	rec[2] = w[2];
	rec[3] = w[3];
	rec[4] = meta_check(w, ctx->ingress_ifindex);
	return XDP_PASS;
}

/* tc: today's pktmeta::resolve. */
SEC("tc")
int hm_tc_cb(struct __sk_buff *skb)
{
	struct counters *c = counters();
	struct meta m;

	if (!c)
		return HM_TCX_NEXT;
	if (read_cb(skb, &m)) {
		c->c[C_TC_CB_HIT]++;
	} else if (parse_skb(skb, &m)) {
		c->c[C_TC_UNPARSED]++;
		return HM_TCX_NEXT;
	} else {
		write_cb(skb, &m);
		c->c[C_TC_PARSE]++;
	}
	use(c, &m);
	return HM_TCX_NEXT;
}

/* tc: resolve, the metadata read through the dynptr before the parse. */
SEC("tc")
int hm_tc_dyn(struct __sk_buff *skb)
{
	struct counters *c = counters();
	struct meta m;
	int got;

	if (!c)
		return HM_TCX_NEXT;
	if (read_cb(skb, &m)) {
		c->c[C_TC_CB_HIT]++;
		goto out;
	}
	got = read_meta_dynptr(skb, &m);
	if (got > 0) {
		write_cb(skb, &m);
		c->c[C_TC_META_HIT]++;
		goto out;
	}
	if (got < 0)
		c->c[C_TC_META_BAD]++;
	if (parse_skb(skb, &m)) {
		c->c[C_TC_UNPARSED]++;
		return HM_TCX_NEXT;
	}
	write_cb(skb, &m);
	c->c[C_TC_PARSE]++;
out:
	use(c, &m);
	return HM_TCX_NEXT;
}

/* tc: every program reads the metadata through the dynptr. */
SEC("tc")
int hm_tc_dyn_all(struct __sk_buff *skb)
{
	struct counters *c = counters();
	struct meta m;
	int got;

	if (!c)
		return HM_TCX_NEXT;
	got = read_meta_dynptr(skb, &m);
	if (got > 0) {
		c->c[C_TC_META_HIT]++;
		goto out;
	}
	if (got < 0)
		c->c[C_TC_META_BAD]++;
	if (read_cb(skb, &m)) {
		c->c[C_TC_CB_HIT]++;
		goto out;
	}
	if (parse_skb(skb, &m)) {
		c->c[C_TC_UNPARSED]++;
		return HM_TCX_NEXT;
	}
	write_cb(skb, &m);
	c->c[C_TC_PARSE]++;
out:
	use(c, &m);
	return HM_TCX_NEXT;
}

/* tc: resolve, the metadata read through data_meta before the parse. */
SEC("tc")
int hm_tc_dmeta(struct __sk_buff *skb)
{
	struct counters *c = counters();
	struct meta m;
	int got;

	if (!c)
		return HM_TCX_NEXT;
	if (read_cb(skb, &m)) {
		c->c[C_TC_CB_HIT]++;
		goto out;
	}
	got = read_meta_direct(skb, &m);
	if (got > 0) {
		write_cb(skb, &m);
		c->c[C_TC_META_HIT]++;
		goto out;
	}
	if (got < 0)
		c->c[C_TC_META_BAD]++;
	if (parse_skb(skb, &m)) {
		c->c[C_TC_UNPARSED]++;
		return HM_TCX_NEXT;
	}
	write_cb(skb, &m);
	c->c[C_TC_PARSE]++;
out:
	use(c, &m);
	return HM_TCX_NEXT;
}

static __hm_inline int same_parse(const struct meta *x, const struct meta *t, __u16 shift)
{
	return x->l3_off - shift == t->l3_off && x->l4_off - shift == t->l4_off &&
	       x->proto == t->proto && x->src_port == t->src_port && x->dst_port == t->dst_port;
}

/* tc, not timed: does the record arrive, and does it say what TC sees? */
SEC("tc")
int hm_tc_probe(struct __sk_buff *skb)
{
	struct meta dm, pm, tm;
	const struct meta *x;
	int dyn, dir;
	__u16 tc_vid;

	pcount(P_RUNS);
	dyn = read_meta_dynptr(skb, &dm);
	dir = read_meta_direct(skb, &pm);
	if (dyn > 0)
		pcount(P_DYNPTR_VALID);
	if (dir > 0)
		pcount(P_DATAMETA_VALID);
	if ((dyn > 0) != (dir > 0))
		pcount(P_READERS_DIFFER);
	if (dyn <= 0 && dir <= 0) {
		if (dyn < 0 || dir < 0)
			pcount(P_META_BAD);
		else
			pcount(P_META_ABSENT);
	}
	if (skb->vlan_present)
		pcount(P_SKB_VLAN);

	if (parse_skb(skb, &tm))
		return HM_TCX_NEXT;
	if (tm.flags & FLAG_VLAN)
		pcount(P_TC_INLINE_VLAN);
	if (!(tm.flags & (FLAG_IPV4 | FLAG_IPV6)))
		return HM_TCX_NEXT;
	pcount(P_IP);
	if (dyn <= 0 && dir <= 0)
		return HM_TCX_NEXT;

	x = dyn > 0 ? &dm : &pm;
	if (x->flags & FLAG_VLAN)
		pcount(P_META_VLAN);
	tc_vid = skb->vlan_present ? (skb->vlan_tci & 0x0FFF) : tm.vlan_id;
	if (x->vlan_id == tc_vid)
		pcount(P_VLAN_ID_AGREE);
	if (same_parse(x, &tm, 0)) {
		pcount(P_AGREE);
	} else {
		pcount(P_DISAGREE);
		if (skb->vlan_present && x->l3_off >= VLAN_HLEN && same_parse(x, &tm, VLAN_HLEN))
			pcount(P_AGREE_AFTER_STRIP);
	}
	return HM_TCX_NEXT;
}
