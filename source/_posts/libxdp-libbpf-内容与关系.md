---
title: libxdp && libbpf 内容与关系
date: 2023-09-15 10:47:19
tags: [eBPF, xdp, 未完待续]
categories: [技术分享]
---

# 两者基本功能

文章内容主要来自 https://github.com/xdp-project/xdp-tutorial

> The libbpf library provides both an ELF loader and several BPF helper functions. It understands BPF Type Format (BTF) and implements CO-RE relocation as part of ELF loading, which is where our libelf-devel dependency comes from.
> The libxdp library provides helper functions for loading and installing XDP programs using the XDP multi-dispatch protocol and helper functions for using AF_XDP sockets. The libxdp library uses libbpf and adds extra features on top. In this tutorial you will learn how to write C code using the libxdp and libbpf libraries.

简单来讲，libbpf 提供 elf 的识别加载机制，而 libxdp 则提供加载 xdp 程序的能力用于 AF_XDP 类型的 socket，它在 libbpf 的基础上增加了一些其他特性用于提供 xdp 的高速报文处理能力。

# xdp-tutorial内容学习

## basic

### basic01-xdp-pass

提供了简单的 xdp code，以及加载 xdp program示例

```c
/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

编译以后形成 xdp_pass_kern.o，用于加载到内核，加载方法分为三种:

1. 直接使用 ip 命令，例如`ip link set dev lo xdpgeneric obj xdp_pass_kern.o sec xdp`
2. 使用 xdp-loader，在 xdp-tools 里面的一个工具，`xdp-loader load -m skb lo xdp_pass_kern.o`
3. 使用 xdp-tools 提供的库，直接编写代码加载，更具有灵活性，例如本示例的源代码 xdp_pass_user.c，编译以后直接 `sudo ./xdp_pass_user -d lo`

源码简单看并不复杂，直接调用接口，有关 XDP Program 等可以参考 basic02部分

```
	char filename[] = "xdp_pass_kern.o";
	char progname[] = "xdp_prog_simple";
/* 创建 xdp_opts */
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, bpf_opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts,
                            .open_filename = filename,
                            .prog_name = progname,
                            .opts = &bpf_opts);
/* Create an xdp_program froma a BPF ELF object file */
	prog = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(prog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Couldn't get XDP program %s: %s\n",
			progname, errmsg);
		return err;
	}

/* Attach the xdp_program to the net device XDP hook */
	err = xdp_program__attach(prog, cfg.ifindex, cfg.attach_mode, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
			cfg.ifname, errmsg, err);
		return err;
	}
```

### basic02-prog-by-name

除了加载 xdp program，本章就是提供了一个具体实例来演示 XDP program 的能力，先说结果：

1. 加载 xdp_drop_func以后，会将接收到的数据drop掉，在测试中效果就是 ping 是不通的；
2. 加载 xdp_pass_func以后，会将接收到数据 pass，也就是通过，ping 是正常回应的；
3. 先加载 xdp_drop_func再加载 xdp_pass_func则按顺序过，drop 命中则不能 ping 通；

首先利用脚本创建一个虚拟接口，虚拟环境，这个后续埋个坑，后续多多看看这个系列，先建个坑 `linux 网络虚拟环境介绍`。

```shell
$ sudo ../testenv/testenv.sh setup --name veth-basic02
Setting up new environment 'veth-basic02'
Setup environment 'veth-basic02' with peer ip fc00:dead:cafe:1::2.
```

具体 abord 的示例没有测试，ping 的时候会有不通的情况，类似 xdp_drop_func的效果。

### basic03-counting with BPF maps

介绍 BPF 的 maps 功能，主要用统计接口收到的总报文数以及每秒 delta 数据量，用于学习 bpf 中的 maps 存储功能。

```shell
XDP_PASS             139 pkts (         1 pps) period:2.000134
XDP_PASS             141 pkts (         1 pps) period:2.000215
XDP_PASS             143 pkts (         1 pps) period:2.000254
XDP_PASS             145 pkts (         1 pps) period:2.000301
XDP_PASS             147 pkts (         1 pps) period:2.000257
XDP_PASS             149 pkts (         1 pps) period:2.000362
XDP_PASS             151 pkts (         1 pps) period:2.000176
XDP_PASS             153 pkts (         1 pps) period:2.000261
```

相关 map 的一些资料：

1. https://www.edony.ink/deepinsight-of-ebpf-map/
2. https://davidlovezoe.club/wordpress/archives/1044?ref=edony.ink

本示例中`xdp_prog_kern.c`创建 map，然后获取到报文以后就自动从 map 中检索到数据并做+1操作，表示收到一个报文，所以实际创建的 map 只有一个元素，key 是`XDP_PASS`，统计收到报文信息；

`xdp_load_and_stats.c`则是用户态程序，首先加载 ebpf 程序到内核，然后检索 map 中的数据，打印相关数据信息；

# basic04-pinning-maps

相较与 basic03 的代码，basic04并没有大的变化，功能还是相同，只不过将之前 xdp 程序加载 bpf 并读取 map 改为了使用路径的方式，相比更加通用，不仅仅加载 bpf 的程序能够使用，其他模块也可以使用。


```shell
XDP-action  
XDP_ABORTED            0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:2.000290
XDP_DROP               0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:2.000289
XDP_PASS              20 pkts (         1 pps)           2 Kbytes (     0 Mbits/s) period:2.000289
XDP_TX                 0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:2.000289
XDP_REDIRECT           0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:2.000289
```
