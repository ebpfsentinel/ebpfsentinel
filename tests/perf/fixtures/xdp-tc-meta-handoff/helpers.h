/*
 * helpers.h - the few BPF helpers and map macros handoff.bpf.c needs,
 * declared here so the bench builds from the running kernel's vmlinux.h
 * alone, with no libbpf header to fetch. The numbers are the helper ids of
 * enum bpf_func_id, which the UAPI never renumbers.
 *
 * Kept apart from handoff.bpf.c so that build.sh can hand this file to
 * kfunc-externs.py as already declared: the kfuncs the bench calls are
 * named only in handoff.bpf.c and get their prototypes from the BTF.
 */
#ifndef HANDOFF_HELPERS_H
#define HANDOFF_HELPERS_H

#define SEC(name) __attribute__((section(name), used))
#define __hm_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_xdp_adjust_meta)(struct xdp_md *xdp_md, int delta) = (void *)54;

#endif
