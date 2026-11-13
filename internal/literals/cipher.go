// Copyright (c) 2020, The Garble Authors.
// See LICENSE for licensing information.

package literals

import (
	mathrand "math/rand"
	"sync"
)

// cipherVariant is the per-file shape of the literal cipher. Each obfuscated
// file draws its own rotations and round count, so a decoder recognized in one
// binary does not match the decoders of other files byte for byte.
type cipherVariant struct {
	rotA, rotB uint
	rounds     uint32
}

// ownerKey is the key half held by the function which owns a literal. The
// other half is stored next to the ciphertext, so neither decodes alone.
type ownerKey [2]uint64

const (
	// cipherHeaderSize is the literal's key half (16 bytes) plus its nonce (8 bytes).
	cipherHeaderSize = 24

	minCipherRounds = 12
	maxCipherRounds = 20

	// Rotations within two bits of a full turn, in either direction, diffuse
	// too slowly: TestCipherAvalanche rejects (1, 31) even at maxCipherRounds,
	// and (31, 2) below 15 rounds. From minRotation up, the worst key bit flips
	// as many keystream bits at minCipherRounds as at maxCipherRounds.
	minRotation = 3
	maxRotation = 32 - minRotation
)

// cipherVariants lists every variant the generator may draw, in a fixed order.
var cipherVariants = sync.OnceValue(func() []cipherVariant {
	var variants []cipherVariant
	for rotA := uint(minRotation); rotA <= maxRotation; rotA++ {
		for rotB := uint(minRotation); rotB <= maxRotation; rotB++ {
			if rotA == rotB {
				continue
			}
			for rounds := uint32(minCipherRounds); rounds <= maxCipherRounds; rounds++ {
				variants = append(variants, cipherVariant{rotA: rotA, rotB: rotB, rounds: rounds})
			}
		}
	}
	return variants
})

func newCipherVariant(r *mathrand.Rand) cipherVariant {
	variants := cipherVariants()
	return variants[r.Intn(len(variants))]
}

func newOwnerKey(r *mathrand.Rand) ownerKey {
	return ownerKey{r.Uint64(), r.Uint64()}
}

// encode encrypts plain surrounded by junk bytes, returning the ciphertext
// and the bounds of plain within the decoded buffer.
func (v cipherVariant) encode(r *mathrand.Rand, plain []byte, owner ownerKey) (ct string, low, high int) {
	// Junk bytes stop equal literals of different lengths from lining up.
	junk := make([]byte, r.Intn(maxStringJunkBytes-minStringJunkBytes)+minStringJunkBytes)
	r.Read(junk)
	low = r.Intn(len(junk))
	high = low + len(plain)
	header := make([]byte, cipherHeaderSize) // the literal's key half, then the nonce
	r.Read(header)

	body := append(append(junk[:low:low], plain...), junk[low:]...)
	// In counter mode, decoding zeros yields the keystream, so the decoder
	// stays the only implementation of the cipher.
	stream := v.decode(string(header)+string(make([]byte, len(body))), owner[0], owner[1], 0, len(body))
	for i := range body {
		body[i] ^= stream[i]
	}
	return string(header) + string(body), low, high
}
