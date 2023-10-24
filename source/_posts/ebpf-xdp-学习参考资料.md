---
title: ebpf/xdp 学习参考资料
tags: [xdp,eBPF,未完待续]
categories:
  - 技术分享
date: 2023-10-18 16:12:23
---
# 1、XDP-project 开源项目

项目主要是利用 ebpf 处理数据报文（The eXpress Data Patah(XDP) inside the Linux kernel)

开发手册：https://github.com/xdp-project/xdp-tutorial

开发实例：https://github.com/xdp-project/bpf-examples

xdp 开发库：https://github.com/xdp-project/xdp-tools

xdp相关论文：https://github.com/xdp-project/xdp-paper

推荐论文，详细内容后续补充：https://github.com/xdp-project/xdp-paper/blob/master/xdp-the-express-data-path.pdf

# 2、Cilium 开源项目

> Cilium 是一个开源项目，它使用 eBPF 和 XDP 技术来提供网络和安全性的解决方案。Cilium 的主要功能包括：
>
> 1. 提供基于 API 的网络连接和安全性策略，以替代传统的基于 IP 和端口的策略。
> 2. 提供负载均衡、网络策略、网络路由等功能。
> 3. 提供透明的安全性，包括 TLS 加密、访问控制等。
> 4. 提供对 Kubernetes 的深度集成，包括 CNI 插件、网络策略、服务发现等。
>    总的来说，eBPF 和 XDP 提供了一种在内核中运行自定义程序的能力，而 Cilium 则利用这种能力来提供高级的网络和安全性功能。

开源项目文档，内容非常的全面：https://docs.cilium.io/en/stable/

其中对 bpf 的介绍也很细致，正在学习中：https://docs.cilium.io/en/latest/bpf/

**Cilium项目内容很多，后续可以重点关注内容实现**
