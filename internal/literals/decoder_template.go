// Copyright (c) 2020, The Garble Authors.
// See LICENSE for licensing information.

package literals

// This file is both garble's own literal decoder and the source of the decoder
// emitted into every obfuscated file; see emitDecoder. The emitted copy is
// compiled as part of user packages, so decode must follow these rules:
//
//   - It must compile at any language version a module can declare: no
//     generics, no range over an integer, no min, max or clear, no conversions
//     from slices to arrays or array pointers, and no signed shift counts.
//   - It may use builtins only: no imports, and no calls to other functions.
//     Rotations are spelled out as x<<a | x>>(32-a).
//   - The receiver v may only appear as v.rotA, v.rotB and v.rounds, which are
//     replaced by the variant's constants.
//   - It must be a pure function of its arguments, as global factories which
//     call it are certified to be free of side effects.

// decode is Speck64/128 in counter mode, with rotations and round count taken
// from the variant. The 128-bit key is ct[:16] XORed with the owner's key
// o0 and o1, the 64-bit nonce is ct[16:24], and the ciphertext follows.
// It returns a fresh buffer with the junk around [low, high) cut off.
func (v cipherVariant) decode(ct string, o0, o1 uint64, low, high int) []byte {
	var w [4]uint32
	for i := 0; i < 4; i++ {
		w[i] = uint32(ct[4*i]) | uint32(ct[4*i+1])<<8 | uint32(ct[4*i+2])<<16 | uint32(ct[4*i+3])<<24
	}
	w[0] ^= uint32(o0)
	w[1] ^= uint32(o0 >> 32)
	w[2] ^= uint32(o1)
	w[3] ^= uint32(o1 >> 32)
	var rk [32]uint32 // must exceed maxCipherRounds
	k, l := w[0], [3]uint32{w[1], w[2], w[3]}
	for i := uint32(0); i < v.rounds; i++ { // Speck key schedule
		rk[i] = k
		n := (k + (l[i%3]>>v.rotA | l[i%3]<<(32-v.rotA))) ^ i
		k = (k<<v.rotB | k>>(32-v.rotB)) ^ n
		l[i%3] = n
	}
	var nonce uint64
	for i := 0; i < 8; i++ {
		nonce |= uint64(ct[16+i]) << (8 * uint(i))
	}
	buf := []byte(ct[24:])
	for j := 0; j < len(buf); j += 8 {
		ctr := nonce + uint64(j/8)
		x, y := uint32(ctr>>32), uint32(ctr)
		for i := uint32(0); i < v.rounds; i++ {
			x = ((x>>v.rotA | x<<(32-v.rotA)) + y) ^ rk[i]
			y = (y<<v.rotB | y>>(32-v.rotB)) ^ x
		}
		blk := uint64(x)<<32 | uint64(y)
		for n := 0; n < 8 && j+n < len(buf); n++ {
			buf[j+n] ^= byte(blk >> (8 * uint(n)))
		}
	}
	return buf[low:high:high]
}
