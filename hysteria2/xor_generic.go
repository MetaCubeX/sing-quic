//go:build !goexperiment.simd

package hysteria2

func xorRepeating32(dst, src []byte, key *[32]byte) {
	if len(dst) < len(src) {
		panic("hysteria2: xor destination is too short")
	}
	for i, value := range src {
		dst[i] = value ^ key[i&31]
	}
}
