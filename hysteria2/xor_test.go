package hysteria2

import (
	"bytes"
	"strconv"
	"testing"
)

func referenceXOR(dst, src []byte, key *[32]byte) {
	for i, value := range src {
		dst[i] = value ^ key[i&31]
	}
}

func TestXORRepeating32(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i*7 + 3)
	}
	lengths := []int{0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 511, 512, 1200, 2048, 4096}
	for _, length := range lengths {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			source := make([]byte, length)
			for i := range source {
				source[i] = byte(i*13 + 11)
			}
			want := make([]byte, length)
			referenceXOR(want, source, &key)

			out := make([]byte, length)
			xorRepeating32(out, source, &key)
			if !bytes.Equal(out, want) {
				t.Fatal("out-of-place XOR mismatch")
			}

			inPlace := bytes.Clone(source)
			xorRepeating32(inPlace, inPlace, &key)
			if !bytes.Equal(inPlace, want) {
				t.Fatal("in-place XOR mismatch")
			}

			overlap := make([]byte, length+salamanderSaltLen)
			copy(overlap[salamanderSaltLen:], source)
			xorRepeating32(overlap[:length], overlap[salamanderSaltLen:], &key)
			if !bytes.Equal(overlap[:length], want) {
				t.Fatal("shifted-overlap XOR mismatch")
			}
		})
	}
}

func BenchmarkXORRepeating32(b *testing.B) {
	for _, size := range []int{64, 512, 1200, 2048, 8192} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			var key [32]byte
			src := make([]byte, size)
			dst := make([]byte, size)
			b.SetBytes(int64(size))
			for b.Loop() {
				xorRepeating32(dst, src, &key)
			}
		})
	}
}
