package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type PacketFunction func(*Packet) interface{}

type BinaryFunction func(PacketFunction, int, *TCPComposition, PacketFunction, int, *TCPComposition) (PacketFunction, int, *TCPComposition)

type FeatureFunction func(PacketFunction, int, *TCPComposition) (PacketFunction, int, *TCPComposition)

// Initial functions
func get_IPId(p *Packet) interface{} {
	return p.IPId
}

func get_SrcIp(p *Packet) interface{} {
	return p.SrcIp
}

func get_DstIp(p *Packet) interface{} {
	return p.DstIp
}

func get_SrcPort(p *Packet) interface{} {
	return p.SrcPort
}

func get_DstPort(p *Packet) interface{} {
	return p.DstPort
}

func get_Seq(p *Packet) interface{} {
	return p.Seq
}

func get_Window(p *Packet) interface{} {
	return p.Window
}

// var Initial_set = []PacketFunction{(get_IPId, 1), (get_SrcIp, 1), (get_DstIp, 1), (get_SrcPort, 1), (get_DstPort, 1), (get_Seq, 1), (get_Window, 1)}
var Initial_set = []PacketFunction{
	get_IPId,
	get_SrcIp,
	get_DstIp, 
	get_SrcPort, 
	get_DstPort, 
	get_Seq,
	get_Window,
}

// Binary operations

func checkType(x interface{}) (uint8, bool, uint16, bool, uint32, bool) {
	switch x.(type) {
	case uint8:
		return uint8(x.(uint8)), true, uint16(0), false, uint32(0), false
	case uint16:
		return uint8(0), false, uint16(x.(uint16)), true, uint32(0), false
	case uint32:
		return uint8(0), false, uint16(0), false, uint32(x.(uint32)), true
	default:
		panic("Unsupported type")
	}
}

func falsePairUint8() Pair[uint8, uint8] {
	return Pair[uint8, uint8]{a: 0, b: 0}
}

func falsePairUint16() Pair[uint16, uint16] {
	return Pair[uint16, uint16]{a: 0, b: 0}
}

func falsePairUint32() Pair[uint32, uint32] {
	return Pair[uint32, uint32]{a: 0, b: 0}
}

func liftUints(x interface{}, y interface{}) (Pair[uint8, uint8], bool, Pair[uint16, uint16], bool, Pair[uint32, uint32], bool) {
	x8, x_ok8, x16, x_ok16, x32, x_ok32 := checkType(x)
	y8, y_ok8, y16, y_ok16, y32, _ := checkType(y)
	if x_ok32 {
		if y_ok8 {
			return falsePairUint8(), false, falsePairUint16(), false, Pair[uint32, uint32]{a: x32, b: uint32(y8)}, true
		} else if y_ok16 {
			return falsePairUint8(), false, falsePairUint16(), false, Pair[uint32, uint32]{a: x32, b: uint32(y16)}, true
		} else {
			return falsePairUint8(), false, falsePairUint16(), false, Pair[uint32, uint32]{a: x32, b: y32}, true
		}
	} else if x_ok16 {
		if y_ok8 {
			return falsePairUint8(), false, Pair[uint16, uint16]{a: x16, b: uint16(y8)}, true, falsePairUint32(), false
		} else if y_ok16 {
			return falsePairUint8(), false, Pair[uint16, uint16]{a: x16, b: y16}, true, falsePairUint32(), false
		} else {
			return falsePairUint8(), false, falsePairUint16(), false, Pair[uint32, uint32]{a: uint32(x16), b: y32}, true
		}
	} else if x_ok8 {
		if y_ok8 {	
			return Pair[uint8, uint8]{a: x8, b: y8}, true, falsePairUint16(), false, falsePairUint32(), false
		} else if y_ok16 {
			return falsePairUint8(), false, Pair[uint16, uint16]{a: uint16(x8), b: y16}, true, falsePairUint32(), false
		} else {
			return falsePairUint8(), false, falsePairUint16(), false, Pair[uint32, uint32]{a: uint32(x8), b: y32}, true
		}
	} else {
		panic("Unsupported type")
	}
}

func and_(fa PacketFunction, count_a int, comp_a *TCPComposition, fb PacketFunction, count_b int, comp_b *TCPComposition) (PacketFunction, int, *TCPComposition) {
	return func(p *Packet) interface{} {
		x := (fa)(p)
		y := (fb)(p)
		p8, p8_ok, p16, p16_ok, p32, _ := liftUints(x, y)
		if p8_ok {
			return (p8.a & p8.b)
		} else if p16_ok {
			return (p16.a & p16.b)
		} else {
			return (p32.a & p32.b)
		}
	}, (1 + count_a + count_b), &TCPComposition{"and", []*TCPComposition{comp_a, comp_b}}
}

func or_(fa PacketFunction, count_a int, comp_a *TCPComposition, fb PacketFunction, count_b int, comp_b *TCPComposition) (PacketFunction, int, *TCPComposition) {
	return func(p *Packet) interface{} {
		x := (fa)(p)
		y := (fb)(p)
		p8, p8_ok, p16, p16_ok, p32, _ := liftUints(x, y)
		if p8_ok {
			return (p8.a | p8.b)
		} else if p16_ok {
			return (p16.a | p16.b)
		} else {
			return (p32.a | p32.b)
		}
	}, (1 + count_a + count_b), &TCPComposition{"or", []*TCPComposition{comp_a, comp_b}}
}

func xor_(fa PacketFunction, count_a int, comp_a *TCPComposition, fb PacketFunction, count_b int, comp_b *TCPComposition) (PacketFunction, int, *TCPComposition) {
	return func(p *Packet) interface{} {
		x := (fa)(p)
		y := (fb)(p)
		p8, p8_ok, p16, p16_ok, p32, _ := liftUints(x, y)
		if p8_ok {
			return (p8.a ^ p8.b)
		} else if p16_ok {
			return (p16.a ^ p16.b)
		} else {
			return (p32.a ^ p32.b)
		}
	}, (1 + count_a + count_b), &TCPComposition{"xor", []*TCPComposition{comp_a, comp_b}}
}

var Binary_operations = []BinaryFunction{
	// and_,
	// or_,
	xor_,
	}

// Feature extractions

func lnbitshift_(n int) func(PacketFunction, int, *TCPComposition) (PacketFunction, int, *TCPComposition) {
	return func(f PacketFunction, count int, comp *TCPComposition) (PacketFunction, int, *TCPComposition) {
		return func(p *Packet) interface{} {
			bin := (f)(p)
			bin8, bin8_ok, bin16, bin16_ok, bin32, bin32_ok := checkType(bin)
			if bin8_ok {
				return (bin8 << n)
			} else if bin16_ok {
				return (bin16 << n)
			} else if bin32_ok {
				return (bin32 << n)
			} else {
				panic("Unsupported type")
			}
		}, (count + 1), &TCPComposition{(fmt.Sprintf("lbitshift: %d", n)), []*TCPComposition{comp}}
	}
}

func rnbitshift_(n int) func(PacketFunction, int, *TCPComposition) (PacketFunction, int, *TCPComposition) {
	return func(f PacketFunction, count int, comp *TCPComposition) (PacketFunction, int, *TCPComposition) {
		return func(p *Packet) interface{} {
			bin := (f)(p)
			bin8, bin8_ok, bin16, bin16_ok, bin32, bin32_ok := checkType(bin)
			if bin8_ok {
				return (bin8 >> n)
			} else if bin16_ok {
				return (bin16 >> n)
			} else if bin32_ok {
				return (bin32 >> n)
			} else {
				panic("Unsupported type")
			}
		}, (count + 1), &TCPComposition{(fmt.Sprintf("rbitshift: %d", n)), []*TCPComposition{comp}}
	}
}

func getBytes(bin interface{}) ([]byte, int) {
	if a, ok := bin.(byte); ok {
		return []byte{a}, 1
	} else if a, ok := bin.(uint16); ok {
		bytes := make([]byte, 2)
		binary.BigEndian.PutUint16(bytes, a)
		return bytes, 2
	} else if a, ok := bin.(uint32); ok {
		bytes := make([]byte, 4)
		binary.BigEndian.PutUint32(bytes, a)
		return bytes, 4
	} else {
		panic("Unsupported type")
	}
}

func getUintFromBytes(bytes []byte, n int) interface{} {
	switch n {
	case 1: 
		return bytes[0] 
	case 2:
		return binary.BigEndian.Uint16(bytes)
	case 4:
		return binary.BigEndian.Uint32(bytes)
	default:
		panic("Unsupported byte length")
	}
} 

func lnbyte_(n int) func(PacketFunction, int, *TCPComposition) (PacketFunction, int, *TCPComposition) {
	return func(f PacketFunction, count int, comp *TCPComposition) (PacketFunction, int, *TCPComposition) {
		return func(p *Packet) interface{} {
			bin := (f)(p)
			bytes, length := getBytes(bin)
			n_bytes := Min(length, n)
			return getUintFromBytes(bytes[:n_bytes], n_bytes)
		}, (count + 1), &TCPComposition{(fmt.Sprintf("lbytes: %d", n)), []*TCPComposition{comp}}
	}
}

func rnbyte_(n int) func(PacketFunction, int, *TCPComposition) (PacketFunction, int, *TCPComposition) {
	return func(f PacketFunction, count int, comp *TCPComposition) (PacketFunction, int, *TCPComposition) {
		return func(p *Packet) interface{} {
			bin := (f)(p)
			bytes, length := getBytes(bin)
			Reverse(bytes)
			n_bytes := Min(length, n)
			s_bytes := bytes[:n_bytes]
			Reverse(s_bytes)
			return getUintFromBytes(s_bytes, n_bytes)
		}, (count + 1), &TCPComposition{(fmt.Sprintf("rbytes: %d", n)), []*TCPComposition{comp}}
	}
}

var Feature_extractions = []FeatureFunction{
	lnbyte_(1),
	lnbyte_(2),
	rnbyte_(1),
	rnbyte_(2),
}

func PrintFingerprints(fingerprints []*Fingerprint, compositions []*TCPComposition) {
	for i, fingerprint := range fingerprints {
		fmt.Printf("%s\n", SprintFingerprint(fingerprint, i, compositions))
	}
}

func SprintFingerprint(fgpt *Fingerprint, i int, compositions []*TCPComposition) string {
	init := ""
	init += fmt.Sprintf("Fingerprint %d:\n", i)
	for _, s := range SprintSigns(
		fgpt.signs,
		fgpt.idxs,
		compositions,
	) {
		init += s
	}
	return init
}

func SprintSigns(signs []*Sign, f_indices []int, compositions []*TCPComposition) (ret []string) {
	for i, sign := range signs {
		ret = append(ret, fmt.Sprintf("{ %s, %d }\n", TCPString(compositions[f_indices[i]], 0), sign.b))
		if i < len(signs) - 1 {
			ret = append(ret, fmt.Sprintf("AND\n"))
		}
	}
	return
}

func TCPString(comp *TCPComposition, depth int) (ret string) {
	comp_ := *comp 
	if len(comp_.comp) != 0 {
		init := ""
		for _, sub_comp := range comp_.comp {
			init += (strings.Repeat("  ", depth + 1)) + fmt.Sprintf("%s\n", TCPString(sub_comp, (depth + 1)))
		}
		return strings.Repeat("  ", depth) + fmt.Sprintf("%s:\n%s", comp_.name, init)
	} else {
		return strings.Repeat("  ", depth) + comp_.name
	}
}