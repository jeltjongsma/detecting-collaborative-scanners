package main

import (
	"fmt"
)

type FingerprintFunc func(*Packet) bool

var (
	l2bSeq, _, _ = lnbyte_(2)(get_Seq, 0, nil)
	xorl2bSeqSeq, _, _ = xor_(l2bSeq, 0, nil, get_Seq, 0, nil)
	xorxorl2bSeqSeqDstIp, _, _ = xor_(xorl2bSeqSeq, 0, nil, get_DstIp, 0, nil)

	r2bSeq, _, _ = rnbyte_(1)(get_Seq, 0, nil)
	xorIpIdR2bSeq, _, _ = xor_(r2bSeq, 0, nil, get_IPId, 0, nil)
	xorxorIpIdR2bSeqSeq, _, _ = xor_(xorIpIdR2bSeq, 0, nil, get_Seq, 0, nil)

	fgpts = []FingerprintFunc{fgpt1}
)

func GetPackets(
	splits []*Split,
	f FingerprintFunc,
	n_packets int,
) *FingerprintData {
	packets := make([]*Packet, 0, n_packets)
	for _, spl := range splits {
		for _, p := range spl.packets {
			if f(p) {
				packets = append(packets, p)
			}
		}
	}

	sources := make(map[uint32]int)
	ports := make(map[uint16]int)
	for _, p := range packets {
		if _, ok := sources[p.SrcIp]; ok {
			sources[p.SrcIp] += 1
		} else {
			sources[p.SrcIp] = 1
		}
		if _, ok := ports[p.DstPort]; ok {
			ports[p.DstPort] += 1
		} else {
			ports[p.DstPort] = 1
		}
	}

	return &FingerprintData{
		packets:	packets,
		sources:	sources,
		n_sources:	len(sources),
		ports:		ports,
		n_ports:	len(ports),
	}
}

func SprintFingerprintData(data *FingerprintData, size float64) (str string) {
	str += fmt.Sprintf("N packets: %d, fraction: %f\n", len(data.packets), float64(len(data.packets)) / size)
	str += fmt.Sprintf("N sources: %d\n", data.n_sources)
	if data.n_sources < 50 {
		for source, count := range data.sources {
			str += fmt.Sprintf("  %s: %d\n", uint32ToIP(source), count)
		}
	}
	str += fmt.Sprintf("N ports: %d\n", data.n_ports)
	if data.n_ports < 20 {
		for port, count := range data.ports {
			str += fmt.Sprintf("  %s: %d\n", port, count)
		}
	}
	return
}

func uint32ToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip))
}