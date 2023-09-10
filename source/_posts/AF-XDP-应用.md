---
title: AF-XDP 应用
date: 2023-09-09 20:09:16
tags: [xdp,eBPF]
categories: [技术分享]
---
AF-XDP，来源与 XDP，XDP 又是衍生与 eBPF，eBPF又生与N 久前的 BPF。

讲来讲去感觉是一连串，于是就有了这么个一个小系列，想把这一块捋清楚讲明白，我也探究一下子传说中的 XDP 真的辣么牛x么。本着自己学习技术的逻辑，先把技术跑起来，应用搞通，再从外到内探究起来，本章就先说一下 af-xdp 在 suricata 中的应用。

# AF-XDP 在 suricata 跑起来


1. 申请个 vpc
   最近这几年真的对云服务器深有爱意，也推荐一下腾讯云，申请一个`竞价实例`是真的便宜。用作测试确实是真的方便，今天申请了一个`Ubuntu Server 22.04 LTS 64 + 8CPU + 32G` 的设备，每小时 4 毛钱，用完销毁即可。
2. 安装 xdp-tool

   ```shell
   # 先更新一下环境
   sudo apt update && sudo apt upgrade
   # 有可能更新内核，需要重启一下系统
   reboot

   # xdp-tool编译所需
   sudo apt install -y pkg-config clang m4 linux-tools-`uname -r` libelf-dev libpcap-dev

   # 更新一下 git，install 的超慢～
   sudo add-apt-repository ppa:git-core/ppa
   sudo apt update
   sudo apt install git

   # 编译安装 libxdp
   git clone https://github.com/xdp-project/xdp-tools.git
   cd xdp-tools
   ./configure
   sudo make install
   # 默认 libbpf 没有安装，需要手动安装，后续编译 suricata 会使用到
   cd lib/libbpf/src
   sudo make install
   sudo echo "/usr/lib64/" > /etc/ld.so.conf.d/bpf.conf #权限不通过则 vim 编辑添加
   sudo ldconfig


   ```
3. 编译 suricata

   ```shell
   git clone https://github.com/OISF/suricata.git
   cd suricata
   git clone https://github.com/OISF/libhtp
   sudo apt-get install libtool libpcre2-dev libyaml-dev libjansson-dev rustc cargo cbindgen 
   ./autogen.sh
   ./configure --enable-xdp --enable-ebpf --enable-ebpf-build --prefix=/home/ubuntu/suricata-test
   make -j
   make install-full
   # 检查安装
   /home/ubuntu/suricata-test/bin/suricata --build-info

   ```
4. 运行
   默认直接运行代码中内容即可，但是 vpc 情况下网卡为虚拟，启动起来没有收包线程，需要做一下修改(runmode-af-xdp.c)

   ```c
       if (aconf->threads > nr_queues) {
           SCLogWarning(
                   "Selected threads greater than configured queues, using: %d thread(s)", nr_queues);
           //aconf->threads = nr_queues;
           aconf->threads = 1;
       }
   ```

   直接带参数运行即可，运行一会 `ctrl+c`停掉服务，可以看到收包信息：

   ```shell
   ubuntu@VM-32-7-ubuntu:~/suricata-suricata-7.0.0/src$ sudo /home/ubuntu/suricata-test/bin/suricata --af-xdp=eth0
   i: suricata: This is Suricata version 7.0.0 RELEASE running in SYSTEM mode
   W: detect: No rule files match the pattern /home/ubuntu/suricata-test/var/lib/suricata/rules/suricata.rules
   W: detect: 1 rule files specified, but no rules were loaded!
   W: af-xdp: Selected threads greater than configured queues, using: 0 thread(s)
   W: af-xdp: Incorrect af-xdp xdp-mode setting, default (none) shall be applied
   libbpf: elf: skipping unrecognized data section(8) .xdp_run_config
   libbpf: elf: skipping unrecognized data section(9) xdp_metadata
   libbpf: elf: skipping unrecognized data section(7) xdp_metadata
   libbpf: prog 'xdp_pass': BPF program load failed: Invalid argument
   libbpf: prog 'xdp_pass': failed to load: -22
   libbpf: failed to load object '/usr/local/lib/bpf/xdp-dispatcher.o'
   libbpf: elf: skipping unrecognized data section(7) xdp_metadata
   libbpf: elf: skipping unrecognized data section(7) xdp_metadata
   libbpf: elf: skipping unrecognized data section(7) xdp_metadata
   i: threads: Threads created -> W: 1 FM: 1 FR: 1   Engine started.
   ^Ci: suricata: Signal Received.  Stopping engine.
   i: device: eth0: packets: 51, drops: 0 (0.00%), invalid chksum: 0

   ```


# AF-XDP 在 suricata 的代码

改天更新...
