// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package scrypt implements the scrypt key derivation function as defined in
// Colin Percival's paper "Stronger Key Derivation via Sequential Memory-Hard
// Functions" (https://www.tarsnap.com/scrypt/scrypt.pdf).
package scrypt

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"

	"github.com/weatheringocean/crypto/pbkdf2"
)

const maxInt = int(^uint(0) >> 1)

// blockCopy copies n numbers from src into dst.
func blockCopy(dst, src []uint32, n int) {
	copy(dst, src[:n])
}

// blockXOR XORs numbers from dst with n numbers from src.
func blockXOR(dst, src []uint32, n int) {
	for i, v := range src[:n] {
		dst[i] ^= v
	}
}

// salsaXOR applies Salsa20/8 to the XOR of 16 numbers from tmp and in,
// and puts the result into both tmp and out.
func salsaXOR(tmp *[16]uint32, in, out []uint32) {
	w0 := tmp[0] ^ in[0]
	w1 := tmp[1] ^ in[1]
	w2 := tmp[2] ^ in[2]
	w3 := tmp[3] ^ in[3]
	w4 := tmp[4] ^ in[4]
	w5 := tmp[5] ^ in[5]
	w6 := tmp[6] ^ in[6]
	w7 := tmp[7] ^ in[7]
	w8 := tmp[8] ^ in[8]
	w9 := tmp[9] ^ in[9]
	w10 := tmp[10] ^ in[10]
	w11 := tmp[11] ^ in[11]
	w12 := tmp[12] ^ in[12]
	w13 := tmp[13] ^ in[13]
	w14 := tmp[14] ^ in[14]
	w15 := tmp[15] ^ in[15]

	x0, x1, x2, x3, x4, x5, x6, x7, x8 := w0, w1, w2, w3, w4, w5, w6, w7, w8
	x9, x10, x11, x12, x13, x14, x15 := w9, w10, w11, w12, w13, w14, w15

	for i := 0; i < 8; i += 2 {
		x4 ^= bits.RotateLeft32(x0+x12, 7)
		x8 ^= bits.RotateLeft32(x4+x0, 9)
		x12 ^= bits.RotateLeft32(x8+x4, 13)
		x0 ^= bits.RotateLeft32(x12+x8, 18)

		x9 ^= bits.RotateLeft32(x5+x1, 7)
		x13 ^= bits.RotateLeft32(x9+x5, 9)
		x1 ^= bits.RotateLeft32(x13+x9, 13)
		x5 ^= bits.RotateLeft32(x1+x13, 18)

		x14 ^= bits.RotateLeft32(x10+x6, 7)
		x2 ^= bits.RotateLeft32(x14+x10, 9)
		x6 ^= bits.RotateLeft32(x2+x14, 13)
		x10 ^= bits.RotateLeft32(x6+x2, 18)

		x3 ^= bits.RotateLeft32(x15+x11, 7)
		x7 ^= bits.RotateLeft32(x3+x15, 9)
		x11 ^= bits.RotateLeft32(x7+x3, 13)
		x15 ^= bits.RotateLeft32(x11+x7, 18)

		x1 ^= bits.RotateLeft32(x0+x3, 7)
		x2 ^= bits.RotateLeft32(x1+x0, 9)
		x3 ^= bits.RotateLeft32(x2+x1, 13)
		x0 ^= bits.RotateLeft32(x3+x2, 18)

		x6 ^= bits.RotateLeft32(x5+x4, 7)
		x7 ^= bits.RotateLeft32(x6+x5, 9)
		x4 ^= bits.RotateLeft32(x7+x6, 13)
		x5 ^= bits.RotateLeft32(x4+x7, 18)

		x11 ^= bits.RotateLeft32(x10+x9, 7)
		x8 ^= bits.RotateLeft32(x11+x10, 9)
		x9 ^= bits.RotateLeft32(x8+x11, 13)
		x10 ^= bits.RotateLeft32(x9+x8, 18)

		x12 ^= bits.RotateLeft32(x15+x14, 7)
		x13 ^= bits.RotateLeft32(x12+x15, 9)
		x14 ^= bits.RotateLeft32(x13+x12, 13)
		x15 ^= bits.RotateLeft32(x14+x13, 18)
	}
	x0 += w0
	x1 += w1
	x2 += w2
	x3 += w3
	x4 += w4
	x5 += w5
	x6 += w6
	x7 += w7
	x8 += w8
	x9 += w9
	x10 += w10
	x11 += w11
	x12 += w12
	x13 += w13
	x14 += w14
	x15 += w15

	out[0], tmp[0] = x0, x0
	out[1], tmp[1] = x1, x1
	out[2], tmp[2] = x2, x2
	out[3], tmp[3] = x3, x3
	out[4], tmp[4] = x4, x4
	out[5], tmp[5] = x5, x5
	out[6], tmp[6] = x6, x6
	out[7], tmp[7] = x7, x7
	out[8], tmp[8] = x8, x8
	out[9], tmp[9] = x9, x9
	out[10], tmp[10] = x10, x10
	out[11], tmp[11] = x11, x11
	out[12], tmp[12] = x12, x12
	out[13], tmp[13] = x13, x13
	out[14], tmp[14] = x14, x14
	out[15], tmp[15] = x15, x15
}

func blockMix(tmp *[16]uint32, in, out []uint32, r int) {
	blockCopy(tmp[:], in[(2*r-1)*16:], 16)
	for i := 0; i < 2*r; i += 2 {
		salsaXOR(tmp, in[i*16:], out[i*8:])
		salsaXOR(tmp, in[i*16+16:], out[i*8+r*16:])
	}
}

func integer(b []uint32, r int) uint64 {
	j := (2*r - 1) * 16
	return uint64(b[j]) | uint64(b[j+1])<<32
}

func smix(b []byte, r, N int, v, xy []uint32) {
	var tmp [16]uint32
	R := 32 * r
	x := xy
	y := xy[R:]

	j := 0
	for i := 0; i < R; i++ {
		x[i] = binary.LittleEndian.Uint32(b[j:])
		j += 4
	}
	for i := 0; i < N; i += 2 {
		blockCopy(v[i*R:], x, R)
		blockMix(&tmp, x, y, r)

		blockCopy(v[(i+1)*R:], y, R)
		blockMix(&tmp, y, x, r)
	}
	for i := 0; i < N; i += 2 {
		j := int(integer(x, r) & uint64(N-1))
		blockXOR(x, v[j*R:], R)
		blockMix(&tmp, x, y, r)

		j = int(integer(y, r) & uint64(N-1))
		blockXOR(y, v[j*R:], R)
		blockMix(&tmp, y, x, r)
	}
	j = 0
	for _, v := range x[:R] {
		binary.LittleEndian.PutUint32(b[j:], v)
		j += 4
	}
}

// Key derives a key from the password, salt, and cost parameters, returning
// a byte slice of length keyLen that can be used as cryptographic key.
//
// N is a CPU/memory cost parameter, which must be a power of two greater than 1.
// r and p must satisfy r * p < 2³⁰. If the parameters do not satisfy the
// limits, the function returns a nil byte slice and an error.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
//	dk, err := scrypt.Key([]byte("some password"), salt, 32768, 8, 1, 32)
//
// The recommended parameters for interactive logins as of 2017 are N=32768, r=8
// and p=1. The parameters N, r, and p should be increased as memory latency and
// CPU parallelism increases; consider setting N to the highest power of 2 you
// can derive within 100 milliseconds. Remember to get a good random salt.
func Key(password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	if N <= 1 || N&(N-1) != 0 {
		return nil, errors.New("scrypt: N must be > 1 and a power of 2")
	}
	if uint64(r)*uint64(p) >= 1<<30 || r > maxInt/128/p || r > maxInt/256 || N > maxInt/128/r {
		return nil, errors.New("scrypt: parameters are too large")
	}

	xy := make([]uint32, 64*r)
	v := make([]uint32, 32*N*r)
	b := pbkdf2.Key(password, salt, 1, p*128*r, sha256.New)

	for i := 0; i < p; i++ {
		smix(b[i*128*r:], r, N, v, xy)
	}

	return pbkdf2.Key(password, b, 1, keyLen, sha256.New), nil
}
