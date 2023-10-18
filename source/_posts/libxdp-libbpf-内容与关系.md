---
title: libxdp && libbpf 内容与关系
date: 2023-09-15 10:47:19
tags: [eBPF, xdp]
categories: [技术分享]
---

# 两者基本功能

文章内容主要来自 https://github.com/xdp-project/xdp-tutorial

> The libbpf library provides both an ELF loader and several BPF helper functions. It understands BPF Type Format (BTF) and implements CO-RE relocation as part of ELF loading, which is where our libelf-devel dependency comes from.

> The libxdp library provides helper functions for loading and installing XDP programs using the XDP multi-dispatch protocol and helper functions for using AF_XDP sockets. The libxdp library uses libbpf and adds extra features on top. In this tutorial you will learn how to write C code using the libxdp and libbpf libraries.