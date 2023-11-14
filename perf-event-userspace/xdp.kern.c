// go:build ignore
#include "vmlinux.h"

#include "bpf/bpf_endian.h"
#include "bpf/bpf_helpers.h"
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} xdp_perf_map SEC(".maps");

static long callback(__u32 index, void *ctx) {
  bpf_printk("index: %d", index);
  return 0;
}

struct event {
  __u64 number;
};

SEC("xdp") int xdp_prog_func(struct xdp_md *ctx) {
  __u64 flags = BPF_F_CURRENT_CPU;
  __u64 pkt_size = (__u64)(ctx->data_end - ctx->data);
  flags |= pkt_size << 32;

  // struct perf_event_attr attr = {
  //     .sample_type = PERF_SAMPLE_RAW,
  //     .type = PERF_TYPE_SOFTWARE,
  //     .config = PERF_COUNT_SW_BPF_OUTPUT,
  // };
  //
  struct event ev = {.number = pkt_size};
  if (bpf_perf_event_output(ctx, &xdp_perf_map, flags, &ev,
                            sizeof(struct event))) {
    return XDP_ABORTED;
  }
  return XDP_PASS;
}
