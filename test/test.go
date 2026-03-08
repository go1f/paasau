//go:build ebpf
// +build ebpf

package main

import (
    "log"
    "os"
    "os/signal"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf capture.c -- -I/usr/include/bpf -O2 -g

func main() {
    // 加载 eBPF 程序
    objs := bpfObjects{}
    if err := loadBpfObjects(&objs, nil); err != nil {
        log.Fatal(err)
    }
    defer objs.Close()

    // 附加到 tcp_connect 系统调用
    kp, err := link.Kprobe("tcp_connect", objs.TcpConnect)
    if err != nil {
        log.Fatal(err)
    }
    defer kp.Close()

    // 读取事件
    rd, err := ebpf.NewReader(objs.Events)
    if err != nil {
        log.Fatal(err)
    }

    go func() {
        var event struct {
            Pid  uint32
            Addr [4]uint32
            Port uint16
        }
        for {
            _, err := rd.Read(&event)
            if err != nil {
                log.Printf("error reading event: %s", err)
                continue
            }
            log.Printf("PID %d connecting to %d.%d.%d.%d:%d", 
                event.Pid, event.Addr[0], event.Addr[1], event.Addr[2], event.Addr[3], event.Port)
        }
    }()

    // 等待中断信号
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    <-c
}
