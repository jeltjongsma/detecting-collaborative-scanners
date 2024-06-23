package main 

import (
	"sync"
	"slices"
	"cmp"
	"runtime"
)

type Worker[T, U any] struct {
	id 		int
	tasks 	<-chan T
	results chan<- U 
}

func Function_worker(
	w *Worker[*FunctionJob, *FunctionResult],
	n_split_worker int,
) {
	// Set up split workers
	for functionJob := range w.tasks {
		// Send split jobs to channel
		// Pass wg to splitjob to ensure all results are received

		tasks := make(chan *SplitJob, len(*functionJob.splits))
		results := make(chan *SplitResult)

		for i := 0; i < n_split_worker; i++ {
			go Split_worker(
				&Worker[*SplitJob, *SplitResult]{i * 10000 + w.id, tasks, results},
			)
		}

		var wg sync.WaitGroup
		// var tasksChanWg sync.WaitGroup
		for _, split := range *functionJob.splits {
			wg.Add(1)
			tasks <- &SplitJob{
				function: 	functionJob.function,
				split: 		split,
				wg: 		&wg,
			}
		}
		close(tasks)

		// Launch goroutine that closes results channel when all results are computed
		go func() {
			wg.Wait()
			close(results)
		}()
		// Merge appearances and count size as results are received
		acc_counts := make(map[int]int)
		size := 0
		for splitResult := range results { // map[int]int
			for bin, count := range splitResult.counts {
				if _, ok := acc_counts[bin]; ok {
					acc_counts[bin] += count 
				} else {
					acc_counts[bin] = count
				}
			}
			size += splitResult.size
		}
		// Compute appearance ratio
		appearanceRatios := make([]*AppearanceRatio, 0, len(acc_counts))
		for bin, count := range acc_counts {
			appearanceRatios = append(
				appearanceRatios,
				&AppearanceRatio{
					binary:	bin,
					ratio: 	float64(count) / float64(size),
				},
			)
		}
		// Force garbage collector so acc_counts is removed from memory
		runtime.GC()
		// Find effective signs
		// Sort binaries on appearance ratio
		slices.SortFunc(appearanceRatios, func(a, b *AppearanceRatio) int {
			return -cmp.Compare(a.ratio, b.ratio)
		})
		// Find effective signs based on appearance ratios
		max_idx := -1
		for i := 0; i < Min(functionJob.max_sign, len(appearanceRatios)); i++ {
			ef, err := effective_indicator(
				appearanceRatios[i].ratio,
				Map[*AppearanceRatio, float64](appearanceRatios, func(a *AppearanceRatio) float64 {
					return a.ratio
				}),
			)
			if err == nil && ef > functionJob.sign_thres {
				max_idx = i
			}
		}
		// Return Signs
		if max_idx != -1 {
			for i := 0; i < max_idx; i++ {
				w.results <- &FunctionResult{
					sign:	&Sign{
						f:	functionJob.function,
						b: 	appearanceRatios[i].binary,
					},
					index: 	functionJob.index,
				}
			}
		}
		functionJob.wg.Done()
	}
}

func Split_worker( 
	w *Worker[*SplitJob, *SplitResult],
) {
	for splitJob := range w.tasks {
		size := len(splitJob.split.packets)
		counts := make(map[int]int)
		for _, packet := range splitJob.split.packets {
			binary := splitJob.function(packet)
			if _, ok := counts[LiftInt(binary)]; ok {
				counts[LiftInt(binary)] += 1
			} else {
				counts[LiftInt(binary)] = 1
			}
		}

		w.results <- &SplitResult{
			counts: counts,
			size:	size,
		}
		splitJob.wg.Done()
	}
}

func FilterPacketsWorker(
	w *Worker[*FilterPacketsJob, *FilterPacketsResult],
) {
	for filterPacketsJob := range w.tasks {
		packets := make([]*PacketIndex, 0, 5000)
		ports := make(map[uint16]struct{})
		for i, p := range filterPacketsJob.packets {
			if LiftInt(filterPacketsJob.f_result.sign.f(p)) == filterPacketsJob.f_result.sign.b {
				ports[p.DstPort] = struct{}{}
				packets = append(packets, &PacketIndex{
					split_idx:	filterPacketsJob.split_idx,
					packet_idx:	i,
				})
			}
		}
		w.results <- &FilterPacketsResult{
			idx:		filterPacketsJob.idx,
			n_ports:	len(ports),
			f_idx:		filterPacketsJob.f_result.index,
			packets:	packets,
		}
		filterPacketsJob.wg.Done()
	}
}

func IntersectionWorker(
	w *Worker[*IntersectionJob, *Intersection],
) {
	for j := range w.tasks {
		all_packets := Map[*Intersection, []*PacketIndex](
			j.xs,
			func(a *Intersection) []*PacketIndex {
				return a.packets 
			},
		)
		intersection := intersectAll(all_packets...)
		has_overlap := false
		for _, inter := range j.xs {
			if overlap(j.min_overlap, intersection, inter) {
				has_overlap = true
				all_idxs := Map[*Intersection, []int](
					j.xs,
					func(a *Intersection) []int {
						return a.idxs
					},
				)
				idxs := Reduce[[]int, []int](
					all_idxs,
					[]int{},
					appendIdxs,
				)
				all_f_idxs := Map[*Intersection, []int](
					j.xs,
					func(a *Intersection) []int {
						return a.f_idxs 
					},
				)
				f_idxs := Reduce[[]int, []int](
					all_f_idxs,
					[]int{},
					appendIdxs,
				)
				w.results <- &Intersection{
					idxs:		idxs,
					f_idxs:		f_idxs,
					packets:	intersection,
					size:		len(intersection),
				}
			}
		}

		if !has_overlap {
			for _, inter := range j.xs {
				w.results <- inter
			}
		}
		j.wg.Done()
	}
}

func overlap(
	min_overlap float64,
	intersection []*PacketIndex,
	x *Intersection,
) bool {
	return float64(len(intersection)) > min_overlap * float64(x.size)
}