package grpc

import "math"

func safeUint32[T ~uint | ~int](v T) uint32 {
	if v > T(math.MaxUint32) {
		return math.MaxUint32
	}
	return uint32(v)
}

func safeInt32[T ~int | ~uint](v T) int32 {
	if v > T(math.MaxInt32) {
		return math.MaxInt32
	}
	return int32(v)
}
