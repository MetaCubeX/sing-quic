//go:build goexperiment.simd

package hysteria2

import "simd"

func xorRepeating32(dst, src []byte, key *[32]byte) {
	if len(dst) < len(src) {
		panic("hysteria2: xor destination is too short")
	}
	keyOffset := 0
	for len(src) > 0 {
		chunkLength := min(len(src), len(key)-keyOffset)
		input, loaded := simd.LoadUint8sPart(src[:chunkLength])
		keyVector, keyLoaded := simd.LoadUint8sPart(key[keyOffset : keyOffset+loaded])
		if keyLoaded != loaded {
			panic("hysteria2: inconsistent SIMD vector length")
		}
		input.Xor(keyVector).StorePart(dst[:loaded])
		src = src[loaded:]
		dst = dst[loaded:]
		keyOffset = (keyOffset + loaded) & 31
	}
}
