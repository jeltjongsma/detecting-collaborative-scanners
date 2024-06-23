package main

import (
	"math"
	"fmt"
	"reflect"
	"sync"
)

const MaxInt = int(^uint(0) >> 1)

func Reverse[S ~[]E, E any](s S)  {
    for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
        s[i], s[j] = s[j], s[i]
    }
	return
}

func AsFullList(binaries_w_count []Pair[int, int], n int) []int {
	binaries := make([]int, n)
	for _, bin := range(binaries_w_count) {
		for i := 0; i < bin.b; i++ {
			binaries = append(binaries, bin.a)
		}
	}
	return binaries
}

func Min(x int, y int) int {
	if x < y {
		return x 
	} else {
		return y
	}
}

func Max(x int, y int) int {
	if x > y {
		return x 
	} else {
		return y
	}
}

func Filter[T any](ss []T, test func(T) bool) (ret []T) {
    for _, s := range ss {
        if test(s) {
            ret = append(ret, s)
        }
    }
    return
}

func Map[T, U any](ss []T, m func(T) U) (ret []U) {
	for _, s := range ss {
		ret = append(ret, m(s))
	}
	return
}

func Distinct[T comparable](ss []T) (ret []T) {
	visited := make(map[T]bool)
	for _, s := range ss {
		if _, ok := visited[s]; ok {
			continue 
		}
		ret = append(ret, s)
	}
	return
}

func MapAsList[T, U comparable](m map[T]U, wg *sync.WaitGroup) []Pair[T, U] {
	ret := make([]Pair[T, U], len(m))
	wg.Add(len(m))
	index := 0
	for k, v := range m {
		go func(i int) {
			defer wg.Done()
			ret[i] = Pair[T, U]{k, v}
		}(index)
		index++
	}
	wg.Wait()
	return ret
}

func Sum(arr []int) (sum int) {
	for _, num := range arr {
		sum += num
	}
	return
}

func Reduce[T, U any](arr []T, acc U, r func(U, T) U) U {
	for i := 0; i < len(arr); i++ {
		acc = r(acc, arr[i])
	}
	return acc
}

func Mean(arr []int) float64 {
	return float64(Sum(arr)) / float64(len(arr))
}

func Variance(arr []int) float64 {
	mean := Mean(arr)
	sum := 0.0
	for _, num := range arr {
		sum += math.Pow(float64(num) - mean, 2)
	}
	variance := sum / float64(len(arr))
	return variance
}

func LiftInt(x interface{}) int {
	switch v := x.(type) {
	case uint8:
		return int(x.(uint8))
	case uint16:
		return int(x.(uint16))
	case uint32:
		return int(x.(uint32))
	case int:
		return x.(int)
	default:
		fmt.Println(reflect.TypeOf(v))
		panic("Unsupported type")
	}
	panic("Huh")
}

func InSet[T comparable](
	set map[T]struct{},
	x *T,
) bool {
	_, ok := set[*x]
	return ok
}

func AddToSet[T comparable](
	set map[T]struct{},
	xs ...*T,
) map[T]struct{} {
	for _, x := range xs {
		if !InSet[T](set, x) {
			set[*x] = struct{}{}
		}
	}
	return set
}

func SplitLen(x []*Split) (size int) {
	for _, spl := range x {
		size += spl.size
	}
	return
}

func SplitSimilarity(x, y []*Split, size int) float64 {
	seen := make(map[Packet]struct{}) 
	for _, spl := range x {
		for _, p := range spl.packets {
			seen[*p] = struct{}{}
		}
	}
	
	c := 0.0
	for _, spl := range y {
		for _, p := range spl.packets {
			if InSet[Packet](seen, p) {
				c += 1.0
			}
		}
	}
	return c / float64(size)
}

func WrapRightShift(n uint64, k int, bits int) uint64 {
	k = k % bits
	shift := n >> k
	wrap := n << (bits - k)
	return shift | wrap
}

func WrapLeftShift(n uint64, k int, bits int) uint64 {
	k = k % bits
	shift := n << k
	wrap := n >> (bits - k)
	return shift | wrap
}