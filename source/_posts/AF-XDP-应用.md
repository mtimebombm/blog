---
title: AF-XDP 应用
date: 2023-09-09 20:09:16
tags: [xdp,eBPF]
categories: [技术分享]
---
AF-XDP，来源与 XDP，XDP 又是衍生与 eBPF，eBPF又生与N 久前的 BPF。

讲来讲去感觉是一连串，于是就有了这么个一个小系列，想把这一块捋清楚讲明白，我也探究一下子传说中的 XDP 真的辣么牛x么。本着自己学习技术的逻辑，先把技术跑起来，应用搞通，再从外到内探究起来，本章就先说一下 af-xdp 在 suricata 中的应用。

> AF_XDP 是 kernel v4.18+ 新加入的一个协议族(如AF_INET), 主要使用 XDP 实现(下图是 XDP 的基本原理图). 核心原理是在 kernel NAPI poll 位置(网卡驱动内部实现, 为内核最早RX数据包位置)运行 BPF 程序, 通过不断调用 poll 方法, 最终将数据包送到正确的XDP程序处理.

# AF-XDP 在 suricata 跑起来

## 申请 CVM

最近这几年真的对云服务器深有爱意，也推荐一下腾讯云，申请一个`竞价实例`是真的便宜。用作测试确实是真的方便，今天申请了一个`Ubuntu Server 22.04 LTS 64 + 8CPU + 32G` 的设备，每小时 4 毛钱，用完销毁即可。

## 安装 xdp-tool

```shell
# 先更新一下环境
sudo apt update && sudo apt upgrade
# 有可能更新内核，需要重启一下系统
reboot

# xdp-tool编译所需库
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

## 编译 suricata

```shell
# 下载代码，也可以使用release的版本
git clone https://github.com/OISF/suricata.git
cd suricata
git clone https://github.com/OISF/libhtp

# 安装所需库，每个环境不同，可以根据configure的错误信息添加所需
sudo apt-get install libtool libpcre2-dev libyaml-dev libjansson-dev rustc cargo cbindgen 

# 编译安装，尽量将安装路径'prefix'指定到普通文件夹，避免过多权限调用
./autogen.sh
./configure --enable-xdp --enable-ebpf --enable-ebpf-build --prefix=/home/ubuntu/suricata-test
make -j
make install-full

# 检查安装
/home/ubuntu/suricata-test/bin/suricata --build-info

```

## 运行

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

# AF-XDP 在 suricata 的代码逻辑

## 配置读取

```yaml
af-xdp:
  - interface: default
    # Number of receive threads. "auto" uses least between the number
    # of cores and RX queues
    #threads: auto
    #disable-promisc: false
    # XDP_DRV mode can be chosen when the driver supports XDP
    # XDP_SKB mode can be chosen when the driver does not support XDP
    # Possible values are:
    #  - drv: enable XDP_DRV mode
    #  - skb: enable XDP_SKB mode
    #  - none: disable (kernel in charge of applying mode)
    #force-xdp-mode: none
    # During socket binding the kernel will attempt zero-copy, if this
    # fails it will fallback to copy. If this fails, the bind fails.
    # The bind can be explicitly configured using the option below.
    # If configured, the bind will fail if not successful (no fallback).
    # Possible values are:
    #  - zero: enable zero-copy mode
    #  - copy: enable copy mode
    #  - none: disable (kernel in charge of applying mode)
    #force-bind-mode: none
    # Memory alignment mode can vary between two modes, aligned and
    # unaligned chunk modes. By default, aligned chunk mode is selected.
    # select 'yes' to enable unaligned chunk mode.
    # Note: unaligned chunk mode uses hugepages, so the required number
    # of pages must be available.
    #mem-unaligned: no
    # The following options configure the prefer-busy-polling socket
    # options. The polling time and budget can be edited here.
    # Possible values are:
    #  - yes: enable (default)
    #  - no: disable
    #enable-busy-poll: yes
    # busy-poll-time sets the approximate time in microseconds to busy
    # poll on a blocking receive when there is no data.
    #busy-poll-time: 20
    # busy-poll-budget is the budget allowed for packet batches
    #busy-poll-budget: 64
    # These two tunables are used to configure the Linux OS's NAPI
    # context. Their purpose is to defer enabling of interrupts and
    # instead schedule the NAPI context from a watchdog timer.
    # The softirq NAPI will exit early, allowing busy polling to be
    # performed. Successfully setting these tunables alongside busy-polling
    # should improve performance.
    # Defaults are:
    #gro-flush-timeout: 2000000
    #napi-defer-hard-irq: 2
```

```c
static void *ParseAFXDPConfig(const char *iface)
{
    ...

    /* default/basic config setup */
    strlcpy(aconf->iface, iface, sizeof(aconf->iface));
    aconf->DerefFunc = AFXDPDerefConfig;
    aconf->threads = 1;
    aconf->promisc = 1;
    aconf->enable_busy_poll = true;
    aconf->busy_poll_time = DEFAULT_BUSY_POLL_TIME;
    aconf->busy_poll_budget = DEFAULT_BUSY_POLL_BUDGET;
    aconf->mode = XDP_FLAGS_UPDATE_IF_NOEXIST;
    aconf->gro_flush_timeout = DEFAULT_GRO_FLUSH_TIMEOUT;
    aconf->napi_defer_hard_irqs = DEFAULT_NAPI_HARD_IRQS;
    aconf->mem_alignment = XSK_UMEM__DEFAULT_FLAGS;
  
    ...
```

## 线程初始化

### xdp相关数据结构

```c
struct UmemInfo {
    void *buf;
    struct xsk_umem *umem;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem_config cfg;
    int mmap_alignment_flag;
};
struct XskSockInfo {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_socket *xsk;

    /* Queue assignment structure */
    struct QueueAssignment queue;

    /* Configuration items */
    struct xsk_socket_config cfg;
    bool enable_busy_poll;
    uint32_t busy_poll_time;
    uint32_t busy_poll_budget;

    struct pollfd fd;
};

```

### 初始化入口函数

```c
static TmEcode ReceiveAFXDPThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    ...
    ptv->iface[AFXDP_IFACE_NAME_LENGTH - 1] = '\0';
    ptv->ifindex = if_nametoindex(ptv->iface);

    ptv->livedev = LiveGetDevice(ptv->iface);
    ...
    ptv->promisc = afxdpconfig->promisc;
    ...

    ptv->threads = afxdpconfig->threads;

    /* Socket configuration */
    ptv->xsk.cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    ptv->xsk.cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    ptv->xsk.cfg.xdp_flags = afxdpconfig->mode;
    ptv->xsk.cfg.bind_flags = afxdpconfig->bind_flags;

    /* UMEM configuration */
    ptv->umem.cfg.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;
    ptv->umem.cfg.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    ptv->umem.cfg.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
    ptv->umem.cfg.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;
    ptv->umem.cfg.flags = afxdpconfig->mem_alignment;

    /* Use hugepages if unaligned chunk mode */
    if (ptv->umem.cfg.flags == XDP_UMEM_UNALIGNED_CHUNK_FLAG) {
        ptv->umem.mmap_alignment_flag = MAP_HUGETLB;
    }

    /* Busy polling configuration */
    ptv->xsk.enable_busy_poll = afxdpconfig->enable_busy_poll;
    ptv->xsk.busy_poll_budget = afxdpconfig->busy_poll_budget;
    ptv->xsk.busy_poll_time = afxdpconfig->busy_poll_time;
    ptv->gro_flush_timeout = afxdpconfig->gro_flush_timeout;
    ptv->napi_defer_hard_irqs = afxdpconfig->napi_defer_hard_irqs;

   
    /* Reserve memory for umem  */
    if (AcquireBuffer(ptv) != TM_ECODE_OK) {
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (AFXDPSocketCreation(ptv) != TM_ECODE_OK) {
        ReceiveAFXDPThreadDeinit(tv, ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }
    ...
}
```

### 创建内存映射umem.buf

```c
static TmEcode AcquireBuffer(AFXDPThreadVars *ptv)
{
    int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS | ptv->umem.mmap_alignment_flag;
    ptv->umem.buf = mmap(NULL, MEM_BYTES, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);

    if (ptv->umem.buf == MAP_FAILED) {
        SCLogError("mmap: failed to acquire memory");
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}
```

### socket的创建

#### AFXDPSocketCreation

af-xdp socket创建入口函数

```c
static TmEcode AFXDPSocketCreation(AFXDPThreadVars *ptv)
{
    // 配置xdpsocket相关的umem信息
    if (ConfigureXSKUmem(ptv) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    // 初始化ring信息
    if (InitFillRing(ptv, NUM_FRAMES * 2) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* Open AF_XDP socket */
    if (OpenXSKSocket(ptv) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    // 创建socket
    if (ConfigureBusyPolling(ptv) != TM_ECODE_OK) {
        SCLogWarning("Failed to configure busy polling"
                     " performance may be reduced.");
    }

    /* Has the eBPF program successfully bound? 
     * 配置xdp相关信息，默认bpf还有一个XDP_FLAGS_HW_MODE，原始代码没有涉及
     * */
#ifdef HAVE_BPF_XDP_QUERY_ID
    if (bpf_xdp_query_id(ptv->ifindex, ptv->xsk.cfg.xdp_flags, &ptv->prog_id)) {
        SCLogError("Failed to attach eBPF program to interface: %s", ptv->livedev->dev);
        SCReturnInt(TM_ECODE_FAILED);
    }
#else
    if (bpf_get_link_xdp_id(ptv->ifindex, &ptv->prog_id, ptv->xsk.cfg.xdp_flags)) {
        SCLogError("Failed to attach eBPF program to interface: %s", ptv->livedev->dev);
        SCReturnInt(TM_ECODE_FAILED);
    }
#endif

    SCReturnInt(TM_ECODE_OK);
}
```

#### ConfigureXSKUmem

```c
static TmEcode ConfigureXSKUmem(AFXDPThreadVars *ptv)
{
    if (xsk_umem__create(&ptv->umem.umem, ptv->umem.buf, MEM_BYTES, &ptv->umem.fq, &ptv->umem.cq,
                &ptv->umem.cfg)) {
        SCLogError("failed to create umem: %s", strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}
```

#### InitFillRing

```c
static TmEcode InitFillRing(AFXDPThreadVars *ptv, const uint32_t cnt)
{
    uint32_t idx_fq = 0;

    uint32_t ret = xsk_ring_prod__reserve(&ptv->umem.fq, cnt, &idx_fq);
    if (ret != cnt) {
        SCLogError("Failed to initialise the fill ring.");
        SCReturnInt(TM_ECODE_FAILED);
    }

    for (uint32_t i = 0; i < cnt; i++) {
        *xsk_ring_prod__fill_addr(&ptv->umem.fq, idx_fq++) = i * FRAME_SIZE;
    }

    xsk_ring_prod__submit(&ptv->umem.fq, cnt);
    SCReturnInt(TM_ECODE_OK);
}
```

#### OpenXSKSocket

```c
tatic TmEcode OpenXSKSocket(AFXDPThreadVars *ptv)
{
    int ret;

    SCMutexLock(&xsk_protect.queue_protect);

    if (AFXDPAssignQueueID(ptv) != TM_ECODE_OK) {
        SCLogError("Failed to assign queue ID");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if ((ret = xsk_socket__create(&ptv->xsk.xsk, ptv->livedev->dev, ptv->xsk.queue.queue_num,
                 ptv->umem.umem, &ptv->xsk.rx, &ptv->xsk.tx, &ptv->xsk.cfg))) {
        SCLogError("Failed to create socket: %s", strerror(-ret));
        SCReturnInt(TM_ECODE_FAILED);
    }
    SCLogDebug("bind to %s on queue %u", ptv->iface, ptv->xsk.queue.queue_num);

    /* For polling and socket options */
    ptv->xsk.fd.fd = xsk_socket__fd(ptv->xsk.xsk);
    ptv->xsk.fd.events = POLLIN;

    /* Set state */
    AFXDPSwitchState(ptv, AFXDP_STATE_UP);

    SCMutexUnlock(&xsk_protect.queue_protect);
    SCReturnInt(TM_ECODE_OK);
}
```

#### ConfigureBusyPolling

> SO_PREFER_BUSY_POLL 是 kernel v5.11 的新加入特性. 据说可提升单核高负载流量下的处理性能. 当启用SO_PREFER_BUSY_POLL后, 调度到软中断 NAPI 上下文执行napi_poll检查到设置此标识, 则立即退出. 避免 busy-polling进程超出调度时间片后与NAPI调度频繁切换, 与SO_BUSY_POLL 相比减少了 NAPI 上下文调度, 提高了收包性能.

```c
static TmEcode ConfigureBusyPolling(AFXDPThreadVars *ptv)
{
    if (!ptv->xsk.enable_busy_poll) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* Kernel version must be >= 5.11 to avail of SO_PREFER_BUSY_POLL
     * see linux commit: 7fd3253a7de6a317a0683f83739479fb880bffc8
     */
    if (!SCKernelVersionIsAtLeast(5, 11)) {
        SCLogWarning("Kernel version older than required: v5.11,"
                     " upgrade kernel version to use 'enable-busy-poll' option.");
        SCReturnInt(TM_ECODE_FAILED);
    }

#if defined SO_PREFER_BUSY_POLL && defined SO_BUSY_POLL && defined SO_BUSY_POLL_BUDGET
    const int fd = xsk_socket__fd(ptv->xsk.xsk);
    int sock_opt = 1;

    if (WriteLinuxTunables(ptv) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, (void *)&sock_opt, sizeof(sock_opt)) < 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    sock_opt = ptv->xsk.busy_poll_time;
    if (setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, (void *)&sock_opt, sizeof(sock_opt)) < 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    sock_opt = ptv->xsk.busy_poll_budget;
    if (setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET, (void *)&sock_opt, sizeof(sock_opt)) < 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
#else
    SCLogWarning(
            "Kernel does not support busy poll, upgrade kernel or disable \"enable-busy-poll\".");
    SCReturnInt(TM_ECODE_FAILED);
#endif
}
```

## 收包

正式主题，进入收包环节，一般suricata这种IDS产品，服务启动以后直接loop收包。

```c
static TmEcode ReceiveAFXDPLoop(ThreadVars *tv, void *data, void *slot)
{
    ...
    AFXDPAllThreadsRunning(ptv);
    TmThreadsSetFlag(tv, THV_RUNNING);
    ...
    while (1) {
        ...

        /* Busy polling is not set, using poll() to maintain (relatively) decent
         * performance. xdp_busy_poll must be disabled for kernels < 5.11
         */
        if (!ptv->xsk.enable_busy_poll) {
            r = poll(&ptv->xsk.fd, 1, POLL_TIMEOUT);

            /* Report poll results */
            if (r <= 0) {
                ...
                continue;
            }
        }

        // 获取收到的报文数
        rcvd = xsk_ring_cons__peek(&ptv->xsk.rx, ptv->xsk.busy_poll_budget, &idx_rx);
        if (!rcvd) {
            ssize_t ret = WakeupSocket(ptv);
            if (ret < 0) {
                SCLogWarning("recv failed with retval %ld", ret);
                AFXDPSwitchState(ptv, AFXDP_STATE_DOWN);
            }
            continue;
        }

        uint32_t res = xsk_ring_prod__reserve(&ptv->umem.fq, rcvd, &idx_fq);
        while (res != rcvd) {
            ssize_t ret = WakeupSocket(ptv);
            if (ret < 0) {
                SCLogWarning("recv failed with retval %ld", ret);
                AFXDPSwitchState(ptv, AFXDP_STATE_DOWN);
                continue;
            }
            res = xsk_ring_prod__reserve(&ptv->umem.fq, rcvd, &idx_fq);
        }

        gettimeofday(&ts, NULL);
        ptv->pkts += rcvd;
        for (uint32_t i = 0; i < rcvd; i++) {
            p = PacketGetFromQueueOrAlloc();
            if (unlikely(p == NULL)) {
                StatsIncr(ptv->tv, ptv->capture_afxdp_acquire_pkt_failed);
                continue;
            }

            PKT_SET_SRC(p, PKT_SRC_WIRE);
            p->datalink = LINKTYPE_ETHERNET;
            p->livedev = ptv->livedev;
            p->ReleasePacket = AFXDPReleasePacket;
            p->flags |= PKT_IGNORE_CHECKSUM;

            p->ts = SCTIME_FROM_TIMEVAL(&ts);

            // 提取地址和长度信息
            uint64_t addr = xsk_ring_cons__rx_desc(&ptv->xsk.rx, idx_rx)->addr;
            uint32_t len = xsk_ring_cons__rx_desc(&ptv->xsk.rx, idx_rx++)->len;
            uint64_t orig = xsk_umem__extract_addr(addr);
            addr = xsk_umem__add_offset_to_addr(addr);

            // 获取原始数据
            uint8_t *pkt_data = xsk_umem__get_data(ptv->umem.buf, addr);

            ptv->bytes += len;

            p->afxdp_v.fq_idx = idx_fq++;
            p->afxdp_v.orig = orig;
            p->afxdp_v.fq = &ptv->umem.fq;

            PacketSetData(p, pkt_data, len);

            // 报文处理
            if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
                TmqhOutputPacketpool(ptv->tv, p);
                SCReturnInt(EXIT_FAILURE);
            }
        }

        // 释放相关数据，从这里看，是批量收取，批量释放，无法使用autofp模式
        xsk_ring_prod__submit(&ptv->umem.fq, rcvd);
        xsk_ring_cons__release(&ptv->xsk.rx, rcvd);

        /* Trigger one dump of stats every second */
        DumpStatsEverySecond(ptv, &last_dump);
    }

    SCReturnInt(TM_ECODE_OK);
}
```
