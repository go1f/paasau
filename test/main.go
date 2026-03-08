//go:build ebpf
// +build ebpf

package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
    "github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf trace.c -- -I/usr/include/bpf -O2 -g

type event struct {
    PID   uint32
    SAddr uint32
    DAddr uint32
    SPort uint16
    DPort uint16
}

func main() {
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal(err)
    }

    objs := bpfObjects{}
    if err := loadBpfObjects(&objs, nil); err != nil {
        log.Fatalf("loading objects: %v", err)
    }
    defer objs.Close()

    kp, err := link.Kprobe("tcp_connect", objs.KprobeTcpConnect, nil)
    if err != nil {
        log.Fatalf("opening kprobe: %v", err)
    }
    defer kp.Close()

    rd, err := perf.NewReader(objs.Events, os.Getpagesize())
    if err != nil {
        log.Fatalf("creating perf event reader: %v", err)
    }
    defer rd.Close()

    go func() {
        var e event
        for {
            record, err := rd.Read()
            if err != nil {
                log.Printf("reading from perf event reader: %v", err)
                continue
            }

            if record.LostSamples != 0 {
                log.Printf("lost %d samples", record.LostSamples)
                continue
            }

            if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
                log.Printf("parsing perf event: %v", err)
                continue
            }

            fmt.Printf("PID %d connecting %s:%d -> %s:%d\n",
                e.PID,
                intToIP(e.SAddr), e.SPort,
                intToIP(e.DAddr), e.DPort)
        }
    }()

    fmt.Println("Tracing tcp_connect... Press Ctrl-C to end")
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    <-c
}

func intToIP(ip uint32) net.IP {
    return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
