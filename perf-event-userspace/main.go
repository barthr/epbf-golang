package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"golang.org/x/sys/unix"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func unlimitLockedMemory() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.kern.c -- -I../libbpf/src -I../common
func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	if err := unlimitLockedMemory(); err != nil {
		log.Fatalf("Failed settin gunlimited memory %s", err)
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	rd, err := perf.NewReader(objs.bpfMaps.XdpPerfMap, 8192)
	if err != nil {
		log.Fatalf("could not open perf reader: %s", err)
	}

	pcap, _ := os.Create("test.pcap")
	defer pcap.Close()
	pcapWriter, err := pcapgo.NewNgWriter(pcap, layers.LinkTypeEthernet)
	if err != nil {
		log.Fatalf("failed instantiating pcap writer: %v", err)
	}
	defer pcapWriter.Flush()

	err = pcapWriter.Flush()
	if err != nil {
		log.Fatalf("failed flushing pcap writer: %v", err)
	}
	for {
		rec, err := rd.Read()

		switch {
		case errors.Is(err, perf.ErrClosed):
			log.Fatalf("failed reading perf record err closed: %v", err)
			continue
		case err != nil:
			log.Fatalf("failed reading perf record: %v", err)
			continue
		}

		if rec.LostSamples > 0 {
			fmt.Errorf("lost %d packets", rec.LostSamples)
			continue
		}

		raw := rec.RawSample
		if len(raw) < 8 {
			fmt.Errorf("perf packet data < 8 bytes: %d", len(raw))
			continue
		}

		packet_length := int(binary.LittleEndian.Uint64(raw[:8]))
		data := raw[8:]

		if packet_length > len(data) {
			fmt.Errorf("length is bigger than packet send from kernel space")
			continue
		}

		packet := data[:packet_length]
		info := gopacket.CaptureInfo{
			Timestamp:      time.Now(),
			CaptureLength:  len(packet),
			Length:         len(packet),
			InterfaceIndex: 0,
		}

		err = pcapWriter.WritePacket(info, packet)
		pcapWriter.Flush()
	}
}
