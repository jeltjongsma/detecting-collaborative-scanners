package main

import (
	"log"
	"math/rand/v2"
	"errors"
)

func Fgpt_ident_iterative(
	splits []*Split,
	n_functions int,
	featext_probability float64,
	initial_set []PacketFunction,
	binary_operations []BinaryFunction,
	feature_extractions []FeatureFunction,
	n_samples int,
	sign_thres float64,
	max_sign int,
	n_iterations int,
	n_packets int,
	seed1 uint64,
	seed2 uint64,
) ([]*Intersection, []*FunctionResult, []*TCPComposition) {

	
	log.Printf("Generating %d functions...\n", n_functions)
	// Generate n functions
	functions, _, compositions := Generate_functions(
		n_functions,
		featext_probability,
		initial_set,
		binary_operations,
		feature_extractions,
	)

	log.Printf("Starting %d iterations)\n", n_iterations)
	all_intersections := make([]*Intersection, 0, 50)
	all_functionResults := make([]*FunctionResult, 0, 100)
	all_bad_functions := make(map[int]struct{})

	var prev_sample []*Split 

	max_samples_tries := n_samples * 10

	too_many_c := 0
	too_little_c := 0
	n_nothing := 0
	n_fingerprinted_packets := 0

	threshold_set := false

	for ; n_iterations > 0; n_iterations-- {
		if sign_thres <= 50.0 {
			log.Printf("SIGN THRESHOLD TOO LOW: 150.0")
			break
		}

		if SplitLen(splits) < n_samples {
			log.Printf("NOT ENOUGH PACKETS LEFT\nReturning results...\n")
			break
		}

		log.Printf("  Iterations left: %d\n", n_iterations)

		visited := make(map[PacketIndex]struct{})
		
		log.Printf("  Sampling %d packets...\n", n_samples)
		sampled_splits, err := Sample_splitsv2(
			splits,
			n_samples,
			// visited,
			max_samples_tries,
			SplitLen(splits),
			WrapRightShift(seed1, n_iterations, 64), 
			WrapLeftShift(seed2, n_iterations, 64), 
		)
		log.Printf("    Got %d samples\n", SplitLen(sampled_splits))
		if err != nil {
			log.Printf("Exceeded max sample tries (%d)\n", max_samples_tries)
			return all_intersections, all_functionResults, compositions
		}

		if prev_sample != nil {
			log.Printf("    Split similarity: %f", SplitSimilarity(prev_sample, sampled_splits, n_samples))	
		}
		prev_sample = sampled_splits

		if n_nothing > 20 && threshold_set {
			log.Printf("Found nothing 20 times. Returning...\n")
			return all_intersections, all_functionResults, compositions
		}
		if too_many_c > 1 {
			sign_thres += 25
			n_iterations += too_many_c
			too_many_c = 0
		}
		if too_little_c > 1 {
			sign_thres -= 25
			too_little_c = 0
		}

		log.Printf("  Computing for sample...\n")
		intersections, functionResults, bad_functions, err := ComputeForSample(
			sampled_splits,
			splits,
			functions,
			sign_thres,
			max_sign,
			all_bad_functions,
			len(all_functionResults), // Use len of all_functionResults to make sure intersection.idxs line up with actual functionResults
		)

		if !threshold_set {
			if err != nil {
				too_many_c++
				continue
			}
			if len(intersections) == 0 {
				too_little_c++
				continue
			}
		}
		if err != nil || len(intersections) == 0 {
			n_nothing++
			continue
		}

		// If we get here then we have found something
		threshold_set = true
		n_nothing = 0

		for _, inter := range intersections {
			all_intersections = AddIntersection(all_intersections, inter)
		}

		all_functionResults = append(
			all_functionResults,
			functionResults...,
		)

		for f_idx, _ := range bad_functions {
			all_bad_functions[f_idx] = struct{}{}
		}

		for _, inter := range intersections {
			visited = AddToSet[PacketIndex](visited, inter.packets...)
		}

		splits = filterSplits(
			visited,
			splits,
		)

		n_fingerprinted_packets += len(visited)
		log.Printf("  Currently fingerprinted %d packets\n", n_fingerprinted_packets)
	}

	return all_intersections, all_functionResults, compositions
}

func filterSplits(
	visited map[PacketIndex]struct{},
	splits []*Split,
) []*Split {
	filtered := make([]*Split, len(splits))
	for i, spl := range splits {
		ps := make([]*Packet, 0, spl.size)
		for p_idx, p := range spl.packets {
			if !InSet[PacketIndex](
				visited,
				&PacketIndex{
					split_idx: 	i,
					packet_idx:	p_idx,
				},
			) {
				ps = append(ps, p)
			}
		}
		filtered[i] = &Split{
			packets:	ps,
			size:		len(ps),
			time:		spl.time,
		}
	}
	return filtered
}

func ComputeForSample(
	sampled_splits []*Split,
	full_splits []*Split,
	functions []PacketFunction,
	sign_thres float64,
	max_sign int,
	bad_functions map[int]struct{},
	startIndex int,
) ([]*Intersection, []*FunctionResult, map[int]struct{}, error) {
	
	log.Printf("    Finding effective signs with threshold: %.0f\n", sign_thres)
	functionResults := find_effective_signs(
		functions, 
		sampled_splits,
		sign_thres,
		max_sign,
		bad_functions,
		56, 
		3,
	)

	if len(functionResults) > 20 {
		log.Printf("Found too many possible signs: %d\n", len(functionResults))
		return []*Intersection{}, functionResults, bad_functions, errors.New("Found too many signs")
	}

	ef_functions := Map[*FunctionResult, PacketFunction](
		functionResults,
		func(x *FunctionResult) PacketFunction {
			return functions[x.index]
		},
	)

	functionResultsFull := find_effective_signs(
		ef_functions,
		full_splits,
		sign_thres * 3,
		max_sign,
		bad_functions,
		56,
		3,
	)

	log.Printf("    Consolidating %d signs...\n", len(functionResults))
	intersections, bad_functions, err := ConsolidateSigns(
		full_splits,
		functionResultsFull,
		225,
		10,
		0.90,
		startIndex,
	)

	if err != nil {
		return intersections, functionResults, bad_functions, errors.New("Found too many true signs")
	}

	return intersections, functionResults, bad_functions, nil
}

func Sample_splitsv2(
	splits []*Split,
	n int,
	max_tries int,
	n_packets int,
	s0 uint64,
	s1 uint64,
) ([]*Split, error) {
	ret := make([]*Split, 0, len(splits))
	s2 := rand.NewPCG(s0, s1)
	r2 := rand.New(s2)
	for _, split := range splits {
		n_samples := n * split.size / n_packets
		samples := make([]*Packet, 0, n_samples)
		seen := make(map[int]struct{})
		for i := 0; i < n_samples; i++ {
			if max_tries < 0 {
				return []*Split{}, errors.New("Unable to sample.")
			}

			r := int(r2.Float64() * float64(split.size))
			if _, ok := seen[r]; ok {
				i--
				max_tries--
				continue
			}

			samples = append(
				samples,
				split.packets[r],
			)
			seen[r] = struct{}{}
		}
		new_split := &Split{
			packets:	samples,
			size:		len(samples),
			time:		split.time,
		}
		ret = append(
			ret,
			new_split,
		)
	}
	return ret, nil
}
