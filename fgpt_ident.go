package main 

import (
	"errors"
	"math/rand/v2"
	"math"
	"sync"
	"log"
	"github.com/montanaflynn/stats"
	"reflect"
)

func find_effective_signs(
	functions []PacketFunction,
	splits []*Split,
	sign_thres float64,
	max_sign int,
	bad_functions map[int]struct{},
	n_function_worker int,
	n_split_worker int,
) []*FunctionResult {
	// Set up channels
	tasks := make(chan *FunctionJob, len(functions))
	results := make(chan *FunctionResult) 

	// Start n workers
	for i := 0; i < n_function_worker; i++ {
		go Function_worker(
			&Worker[*FunctionJob, *FunctionResult]{i, tasks, results},
			n_split_worker,
		)
	}

	var wg sync.WaitGroup
	// Send jobs to channel
	for i, f := range functions {
		// If bad function, dont compute
		if _, ok := bad_functions[i]; ok {
			continue
		}
		wg.Add(1)
		tasks <- &FunctionJob{
			function: 	f,
			index:		i,
			splits:		&splits,
			sign_thres:	sign_thres,
			max_sign:	max_sign,
			wg:			&wg,
		}
	}

	close(tasks)

	go func() {
		wg.Wait()
		close(results)
	}()

	// Turn channel into slice
	ret := make([]*FunctionResult, 0, 150)
	for result := range results {
		ret = append(ret, result)
	}

	return ret
}

func select_random(inp []interface{}) interface{} {
	return inp[rand.IntN(len(inp))]
}

func select_function(
	functions []PacketFunction,
	counts []int,
	compositions []*TCPComposition,
) (PacketFunction, int, *TCPComposition) {
	total_prob := 0.0
	f_probs := make([]float64, len(functions))
	for i, count := range counts {
		f_prob := math.Pow(1.0 / float64(count), 2)
		total_prob += f_prob
		f_probs[i] = f_prob
	}

	r := rand.Float64() * total_prob
	cumCount := 0.0
	for i, c := range f_probs {
		cumCount += c
		if r <= cumCount {
			return functions[i], counts[i], compositions[i]
		}
	}
	i := 0
	return functions[i], counts[i], compositions[i] 
}

func gen_func(
	featext_probability float64, 
	functions []PacketFunction, 
	counts []int,
	compositions []*TCPComposition,
	binary_operations []BinaryFunction,
	feature_extractions []FeatureFunction,
) (PacketFunction, int, *TCPComposition) {
	if rand.Float64() > featext_probability {
		fa, ca, comp_a := select_function(functions, counts, compositions)
		fb, cb, comp_b := select_function(functions, counts, compositions)
		bin_op := binary_operations[rand.IntN(len(binary_operations))]
		return bin_op(fa, ca, comp_a, fb, cb, comp_b)
	} else {
		f, c, comp := select_function(functions, counts, compositions)
		feat_ext := feature_extractions[rand.IntN(len(feature_extractions))]
		return feat_ext(f, c, comp)
	}
}

func Generate_functions(
	n int, 
	featext_probability float64, 
	initial_set []PacketFunction,
	binary_operations []BinaryFunction,
	feature_extractions []FeatureFunction,
) ([]PacketFunction, []int, []*TCPComposition) {
	var functions = initial_set
	var counts = []int{1, 1, 1, 1, 1, 1, 1}
	var compositions = []*TCPComposition{
		&TCPComposition{"Get IP Id", []*TCPComposition{}}, 
		&TCPComposition{"Get Src IP", []*TCPComposition{}},
		&TCPComposition{"Get Dst IP", []*TCPComposition{}},
		&TCPComposition{"Get Src Port", []*TCPComposition{}},
		&TCPComposition{"Get Dst Port", []*TCPComposition{}},
		&TCPComposition{"Get Seq", []*TCPComposition{}},
		&TCPComposition{"Get Window", []*TCPComposition{}},
	}

	for i := 0; i < n; i++ {
		f, c, comp := gen_func(featext_probability, functions, counts, compositions, binary_operations, feature_extractions)
		functions = append(functions, f)
		counts = append(counts, c)
		compositions = append(compositions, comp)
	}

	return functions, counts, compositions
}

func effective_indicator(x float64, appearanceRatios []float64) (float64, error) {
	r_less := Filter[float64](appearanceRatios, func(i float64) bool {return i < x})
	if len(r_less) < 1 {
		return 1, nil
	}
	r_less_var, err := stats.SampleVariance(r_less)
	if err != nil {
		return 0.0, err 
	}

	r_eq_less := Filter[float64](appearanceRatios, func(i float64) bool {return i <= x})
	r_eq_less_var, err := stats.SampleVariance(r_eq_less)
	if err != nil {
		return 0.0, err 
	}

	if r_less_var > 0 {
		return math.Pow(r_eq_less_var, 2) / math.Pow(r_less_var, 2), nil
	} else {
		return 0.0, errors.New("r_less variance less than 0")
	}
}

func ConsolidateSigns(
	splits []*Split,
	signs []*FunctionResult,
	n_workers int,
	max_iterations int,
	min_overlap float64,
	startIndex int,
) ([]*Intersection, map[int]struct{}, error) {
	tasks := make(chan *FilterPacketsJob, len(splits) * len(signs))
	results := make(chan *FilterPacketsResult)

	log.Printf("    Filtering packets by signs...\n")
	for i := 0; i < n_workers; i++ {
		go FilterPacketsWorker(
			&Worker[*FilterPacketsJob, *FilterPacketsResult]{i, tasks, results},
		)
	}

	var wg sync.WaitGroup
	for split_idx, split := range splits {
		for idx, sign := range signs {
			wg.Add(1)
			tasks <- &FilterPacketsJob{
				idx:		idx,
				f_result: 	sign,
				split_idx:	split_idx,
				packets: 	split.packets,	
				wg: 		&wg,
			}
		}
	}
	close(tasks)

	go func() {
		wg.Wait()
		close(results)
	}() 

	bad_functions := make(map[int]struct{})
	// Wrap signs with filtered packets in intersection type
	// intersections := make([]*Intersection, len(signs)) // Signs wrapped in intersection
	set_intersections := make(map[int]*Intersection)
	for result := range results {
		// If too many ports drop sign, because it is likely a bad TCP function
		// Also flag underlying function as "bad"
		if result.n_ports > 20 {
			bad_functions[result.f_idx] = struct{}{}
			continue
		}
		if inter, ok := set_intersections[result.idx]; ok {
			ps := append(inter.packets, result.packets...)
			set_intersections[result.idx] = &Intersection{
				idxs:		inter.idxs,
				f_idxs:		inter.f_idxs,
				packets:	ps,
				size: 		len(ps),
			}
		} else {
			set_intersections[result.idx] = &Intersection{
				idxs:		[]int{startIndex + result.idx},
				f_idxs:		[]int{signs[result.idx].index},
				packets: 	result.packets,
				size:		len(result.packets),
			}
		}
	}

	intersections := make([]*Intersection, 0, len(set_intersections))
	for _, inter := range set_intersections {
		intersections = append(intersections, inter) 
	}

	log.Printf("    Number of true signs: %d\n", len(intersections))
	if len(intersections) > 15 {
		return intersections, bad_functions, errors.New("Too many true signs")
	}
	log.Printf("    Recursively intersecting filtered packets by signs with max iterations: %d\n", max_iterations)
	len_prev_intersections := 0
	for ; math.Abs(float64(len_prev_intersections - len(intersections))) > 0 && max_iterations > 0; max_iterations-- {
		log.Printf("     Iterations left: %d\n", max_iterations)
		len_prev_intersections = len(intersections)

		n_tasks := 1 << len(intersections)

		intTasks := make(chan *IntersectionJob, n_tasks)
		intResults := make(chan *Intersection, n_tasks)

		for i := 0; i < 32; i++ {
			go IntersectionWorker(
				&Worker[*IntersectionJob, *Intersection]{i, intTasks, intResults},
			)
		}
		log.Printf("STARTED WORKERS\n")

		subset := make([]*Intersection, 0, len(intersections))
		generateCombinations(&IntersectionJob{
			xs:				intersections,
			min_overlap: 	min_overlap,
			wg:				&wg,
			startIndex: 	startIndex,
		}, subset, intTasks, 0, 0)
		
		close(intTasks)

		log.Printf("WAITING FOR RESULTS\n")

		go func() {
			wg.Wait()
			close(intResults)
		}()

		new_intersections := make([]*Intersection, 0, len(intersections))
		for result := range intResults {
			// if !intersectionInList(new_intersections, result) {
			// 	new_intersections = append(new_intersections, result)
			// }
			new_intersections = AddIntersection(new_intersections, result)
		}

		log.Printf("    Got %d intersections...\n", len(new_intersections))

		intersections = new_intersections // Replace old intersections with new found ones
	}

	// log.Printf("    Mapping intersections to fingerprints...\n")
	return intersections, bad_functions, nil
	// return Map[*Intersection, *Fingerprint](
	// 	intersections,
	// 	func(x *Intersection) *Fingerprint {
	// 		f_signs := Map[int, *Sign](
	// 			x.idxs,
	// 			func(a int) *Sign {
	// 				return signs[a].sign
	// 			},
	// 		)
	// 		return &Fingerprint{
	// 			signs: 	f_signs,
	// 			idxs:	x.f_idxs,
	// 		}
	// 	},
	// )
}

func AddIntersection(list []*Intersection, item *Intersection) []*Intersection {
	res := make([]*Intersection, 0, len(list)+1)
	added := false
	for _, existing := range list {
		// If an intersection contains less signs then new one, then it could be the same intersection with less signs
		if len(existing.idxs) <= len(item.idxs) && containsAll(item.idxs, existing.idxs) {
			added = true
			res = append(res, item)
		// Larger intersection could also already be added
		} else if len(item.idxs) <= len(existing.idxs) && containsAll(existing.idxs, item.idxs) {
			added = true 
			res = append(res, existing)
		// If neither the case add original back
		} else {
			res = append(res, existing)
		}
	}
	// If new intersection not added then add now
	if !added {
		res = append(res, item)
	}
	return res
}

// Check if xs contains all elements from ys
func containsAll(xs, ys []int) bool {
	// Map to set
	set := make(map[int]struct{})
	for _, x := range xs {
		set[x] = struct{}{}
	}
	// Check if all elements from ys are in xs
	// If not then false else true
	for _, y := range ys {
		if _, ok := set[y]; !ok {
			return false
		}
	}
	return true
}

// If intersection in list return true, else false
func intersectionInList(list []*Intersection, item *Intersection) bool {
	for _, existing := range list {
		if reflect.DeepEqual(existing.idxs, item.idxs) {
			return true
		}
	}
	return false
}

func intersect(x, y []*PacketIndex) []*PacketIndex {
	set := make(map[PacketIndex]struct{})
	for _, idx := range x {
		set[*idx] = struct{}{}
	}

	intersection := make([]*PacketIndex, 0, 100000)
	for _, idx := range y {
		if _, ok := set[*idx]; ok {
			intersection = append(intersection, idx)
		}
	} 
	
	return intersection
}

func intersectAll(xs ...[]*PacketIndex) []*PacketIndex {
	inter := xs[0]
	for i := 1; i < len(xs); i++ {
		inter = intersect(inter, xs[i])
	}
	return inter
}

func appendIdxs(x, y []int) (ret []int) {
	seen := make(map[int]struct{})
	ret = make([]int, 0, len(x) + len(y) / 2)
	for _, i := range x {
		seen[i] = struct{}{}
		ret = append(ret, i)
	}
	for _, i := range y {
		if _, ok := seen[i]; ok {
			continue
		}
		ret = append(ret, i)
	}
	return
}

func generateCombinations(
	job *IntersectionJob,
	subset []*Intersection,
	tasks chan *IntersectionJob,
	index int,
	count int,
) {
	temp := make([]*Intersection, len(subset))
	copy(temp, subset)
	if len(temp) > 0 {
		job.wg.Add(1)
		tasks <- &IntersectionJob{
			xs:				temp,	
			min_overlap:	job.min_overlap,
			wg:				job.wg,
			startIndex:		job.startIndex,
		}
	}

	for i := index; i < len(job.xs); i++ {
		subset = append(subset, job.xs[i])

		generateCombinations(job, subset, tasks, i+1, count + i - index)

		subset = subset[:len(subset)-1]
	}
}