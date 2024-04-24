// +build ignore

#include "vmlinux.h"

#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "socket_defs.h"

struct config {
	char comm[16];
};

static volatile const struct config CFG = {};

union ip6 {
	__u8 u6_addr8[16];
	__be16 u6_addr16[8];
	__be32 u6_addr32[4];
	__be64 u6_addr64[2];
};

struct tuple {
	union ip6 sip;
	union ip6 dip;
	__u16 sport;
	__u16 dport;
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct tuple);
	__type(value, __u64);
	__uint(max_entries, 65535);
} fast_sock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct tuple);
	__type(value, bool);
	__uint(max_entries, 256);
} local_sock SEC(".maps");

SEC("sockops")
int tcp_sockops(struct bpf_sock_ops *skops)
{
	char comm[16];
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	BPF_CORE_READ_STR_INTO(&comm, task, comm);
	if (bpf_strncmp(comm, 16, (void *)CFG.comm) != 0)
		return 0;

	struct tuple tuple = {};
	if (skops->family == AF_INET) {
		tuple.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuple.sip.u6_addr32[3] = skops->local_ip4;
		tuple.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuple.dip.u6_addr32[3] = skops->remote_ip4;
	} else if (skops->family == AF_INET6) {
		tuple.sip.u6_addr32[3] = skops->local_ip6[3];
		tuple.sip.u6_addr32[2] = skops->local_ip6[2];
		tuple.sip.u6_addr32[1] = skops->local_ip6[1];
		tuple.sip.u6_addr32[0] = skops->local_ip6[0];
		tuple.dip.u6_addr32[3] = skops->remote_ip6[3];
		tuple.dip.u6_addr32[2] = skops->remote_ip6[2];
		tuple.dip.u6_addr32[1] = skops->remote_ip6[1];
		tuple.dip.u6_addr32[0] = skops->remote_ip6[0];
	} else {
		return 0;
	}

	tuple.sport = bpf_htonl(skops->local_port) >> 16;
	tuple.dport = skops->remote_port >> 16;

	switch (skops->op) {

	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		if (!bpf_sock_hash_update(skops, &fast_sock, &tuple, BPF_ANY)) {
			if (skops->family == AF_INET)
				bpf_printk("v4 fast_sock added: %pI4:%lu -> %pI4:%lu",
					   &tuple.sip.u6_addr32[3],
					   bpf_ntohs(tuple.sport),
					   &tuple.dip.u6_addr32[3],
					   bpf_ntohs(tuple.dport));
			else
				bpf_printk("v6 fast_sock added: %pI6:%lu -> %pI6:%lu",
					   &tuple.sip.u6_addr32,
					   bpf_ntohs(tuple.sport),
					   &tuple.dip.u6_addr32,
					   bpf_ntohs(tuple.dport));
		}

		break;

	default:
		break;
	}

	return 0;
}

SEC("sk_msg/fast_redirect")
int sk_msg_fast_redirect(struct sk_msg_md *msg)
{
	struct tuple rev_tuple = {};
	rev_tuple.sport = msg->remote_port >> 16;
	rev_tuple.dport = bpf_htonl(msg->local_port) >> 16;
	if (msg->family == AF_INET) {
		rev_tuple.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		rev_tuple.sip.u6_addr32[3] = msg->remote_ip4;
		rev_tuple.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		rev_tuple.dip.u6_addr32[3] = msg->local_ip4;
	} else if (msg->family == AF_INET6) {
		rev_tuple.sip.u6_addr32[3] = msg->remote_ip6[3];
		rev_tuple.sip.u6_addr32[2] = msg->remote_ip6[2];
		rev_tuple.sip.u6_addr32[1] = msg->remote_ip6[1];
		rev_tuple.sip.u6_addr32[0] = msg->remote_ip6[0];
		rev_tuple.dip.u6_addr32[3] = msg->local_ip6[3];
		rev_tuple.dip.u6_addr32[2] = msg->local_ip6[2];
		rev_tuple.dip.u6_addr32[1] = msg->local_ip6[1];
		rev_tuple.dip.u6_addr32[0] = msg->local_ip6[0];
	} else {
		return SK_PASS;
	}


	if (msg->family == AF_INET)
		bpf_printk("v4 tcp fast redirect: size=%lld %pI4:%lu -> %pI4:%lu",
			   msg->size,
			   &rev_tuple.dip.u6_addr32[3],
			   bpf_ntohs(rev_tuple.dport),
			   &rev_tuple.sip.u6_addr32[3],
			   bpf_ntohs(rev_tuple.sport));
	else
		bpf_printk("v6 tcp fast redirect: size=%lld %pI6:%lu -> %pI6:%lu",
			   msg->size,
			   &rev_tuple.dip.u6_addr32,
			   bpf_ntohs(rev_tuple.dport),
			   &rev_tuple.sip.u6_addr32,
			   bpf_ntohs(rev_tuple.sport));

	return bpf_msg_redirect_hash(msg, &fast_sock, &rev_tuple, BPF_F_INGRESS);
}

SEC("license") const char __license[] = "Dual BSD/GPL";
