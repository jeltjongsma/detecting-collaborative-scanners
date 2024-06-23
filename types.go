package main

import (
	"sync"
	"context"
    "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type Packet struct {
    IPId 	uint16
    SrcIp 	uint32
    DstIp 	uint32
    SrcPort uint16
    DstPort uint16
    Seq 	uint32
    Window 	uint16
}

type Split struct {
	packets []*Packet
	size 	int
	time 	string
}

type PacketIndex struct {
	split_idx 	int 
	packet_idx	int
}

type Intersection struct {
	idxs 	[]int
	f_idxs	[]int
	packets []*PacketIndex
	size 	int 
}

type Pair[T, U any] struct {
	a T 
	b U 
}

type Sign struct {
	f PacketFunction
	b int
}

type Fingerprint struct {
 	signs 	[]*Sign
	idxs 	[]int
}

type TCPComposition struct {
	name 	string
	comp	[]*TCPComposition
}

type FunctionJob struct {
	function 	PacketFunction
	index 		int
	splits 		*[]*Split
	sign_thres 	float64
	max_sign 	int
	wg 			*sync.WaitGroup
}

type FunctionResult struct {
	sign 		*Sign
	index 		int
}

type SplitJob struct {
	function 	PacketFunction
	split 		*Split
	wg			*sync.WaitGroup
}

type SplitResult struct {
	counts		map[int]int
	size 		int
}

type DatabaseJob struct {
	ctx 		*context.Context 
	conn 		*driver.Conn 
	time 		string	
	limit 		bool
	n_limit 	int
	zmap		bool
	wg 			*sync.WaitGroup
}

type FilterPacketsJob struct {
	idx 		int 
	f_result	*FunctionResult
	split_idx 	int 
	packets 	[]*Packet
	wg 			*sync.WaitGroup
}

type FilterPacketsResult struct {
	idx 	int 
	n_ports int
	f_idx 	int
	packets []*PacketIndex
}

type IntersectionJob struct {
	xs 			[]*Intersection
	min_overlap float64
	wg 			*sync.WaitGroup
	startIndex 	int
}

type AppearanceRatio struct {
	binary 	int 
	ratio 	float64
}

type CountEffectiveFunctionsResult struct {
	sign_thres	float64
	n_func 		int
}

type HyperparametersResult struct {
	fgpt		*Fingerprint
	n_samples 	int 
	sign_thres 	float64
	n_signs 	int
	signs		[]*FunctionResult
	zmap 		bool
}

type FingerprintData struct{
	packets 	[]*Packet
	sources 	map[uint32]int 
	n_sources 	int
	ports 		map[uint16]int
	n_ports 	int
}