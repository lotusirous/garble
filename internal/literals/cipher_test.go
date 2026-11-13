package literals

import (
	"bytes"
	"fmt"
	"math/bits"
	"math/rand"
	"strings"
	"testing"
)

func TestCipherVariants(t *testing.T) {
	variants := cipherVariants()
	if len(variants) == 0 {
		t.Fatal("no cipher variants")
	}
	seen := make(map[cipherVariant]bool)
	for _, v := range variants {
		if seen[v] {
			t.Fatalf("duplicate variant %+v", v)
		}
		seen[v] = true
		if v.rotA < 1 || v.rotA > 31 || v.rotB < 1 || v.rotB > 31 || v.rotA == v.rotB {
			t.Fatalf("bad rotations in %+v", v)
		}
		if v.rounds < minCipherRounds || v.rounds > maxCipherRounds || maxCipherRounds >= 32 {
			t.Fatalf("bad round count in %+v", v)
		}
	}
	first := newCipherVariant(rand.New(rand.NewSource(1)))
	second := newCipherVariant(rand.New(rand.NewSource(1)))
	if first != second {
		t.Fatalf("variant choice is not deterministic: %+v != %+v", first, second)
	}
}

// sampleVariants returns the first, middle and last variant, so that the
// extremes of the rotation and round ranges are always exercised.
func sampleVariants() []cipherVariant {
	vs := cipherVariants()
	return []cipherVariant{vs[0], vs[len(vs)/2], vs[len(vs)-1]}
}

func TestCipherRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 7, 8, 9, 24, 25, 257, 4096} {
		for seed := int64(1); seed <= 3; seed++ {
			for _, v := range sampleVariants() {
				r := rand.New(rand.NewSource(seed))
				plain := make([]byte, size)
				r.Read(plain)
				owner := newOwnerKey(r)
				ct, low, high := v.encode(r, plain, owner)

				if junk := len(ct) - cipherHeaderSize - len(plain); junk < 2 || junk > 7 {
					t.Fatalf("size %d seed %d %+v: %d junk bytes, want 2..7", size, seed, v, junk)
				}
				got := v.decode(ct, owner[0], owner[1], low, high)
				if got == nil || !bytes.Equal(got, plain) {
					t.Fatalf("size %d seed %d %+v: decoded %x, want %x", size, seed, v, got, plain)
				}
				if len(got) != cap(got) || len(got) != len(plain) {
					t.Fatalf("size %d seed %d %+v: len %d cap %d, want %d", size, seed, v, len(got), cap(got), len(plain))
				}
				if size > 0 {
					got[0] ^= 1
					if again := v.decode(ct, owner[0], owner[1], low, high); !bytes.Equal(again, plain) {
						t.Fatalf("size %d seed %d %+v: a mutated result leaked into the next decode", size, seed, v)
					}
				}
			}
		}
	}
}

func TestCipherSplitKey(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	v := newCipherVariant(r)
	owner := newOwnerKey(r)
	plain := []byte("split key secret literal")
	ct, low, high := v.encode(r, plain, owner)

	if got := v.decode(ct, 0, 0, low, high); bytes.Equal(got, plain) {
		t.Fatal("ciphertext decodes without the owner key")
	}
	noLiteralKey := strings.Repeat("\x00", 16) + ct[16:]
	if got := v.decode(noLiteralKey, owner[0], owner[1], low, high); bytes.Equal(got, plain) {
		t.Fatal("ciphertext decodes without the literal's key half")
	}
}

// TestCipherAvalanche checks that every key bit reaches about half of the
// keystream bits, for every variant the generator may draw.
func TestCipherAvalanche(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	headers := make([][]byte, 3)
	for i := range headers {
		headers[i] = make([]byte, cipherHeaderSize)
		r.Read(headers[i])
	}
	zeros := string(make([]byte, 16))
	var failures []string
	for _, v := range cipherVariants() {
		for _, header := range headers {
			base := v.decode(string(header)+zeros, 0, 0, 0, 16)
			total, minFlips := 0, 128
			for bit := range 128 {
				flipped := bytes.Clone(header)
				flipped[bit/8] ^= 1 << (bit % 8)
				stream := v.decode(string(flipped)+zeros, 0, 0, 0, 16)
				flips := 0
				for i := range stream {
					flips += bits.OnesCount8(stream[i] ^ base[i])
				}
				total += flips
				minFlips = min(minFlips, flips)
			}
			if mean := float64(total) / 128; mean < 57.6 || mean > 70.4 || minFlips < 32 {
				failures = append(failures, fmt.Sprintf("rotA=%d rotB=%d rounds=%d: mean %.1f, min %d",
					v.rotA, v.rotB, v.rounds, mean, minFlips))
				break
			}
		}
	}
	if len(failures) > 0 {
		t.Fatalf("%d variants lack avalanche:\n%s", len(failures), strings.Join(failures, "\n"))
	}
}

func FuzzCipherRoundTrip(f *testing.F) {
	f.Add([]byte(""), int64(1))
	f.Add([]byte("hello, world"), int64(2))
	f.Add(bytes.Repeat([]byte{0xff}, 100), int64(3))
	f.Fuzz(func(t *testing.T, plain []byte, seed int64) {
		r := rand.New(rand.NewSource(seed))
		v := newCipherVariant(r)
		owner := newOwnerKey(r)
		ct, low, high := v.encode(r, plain, owner)
		got := v.decode(ct, owner[0], owner[1], low, high)
		if !bytes.Equal(got, plain) || len(got) != cap(got) {
			t.Fatalf("%+v: decoded %x (cap %d), want %x", v, got, cap(got), plain)
		}
	})
}

func BenchmarkCipherDecode(b *testing.B) {
	var v cipherVariant
	for _, candidate := range cipherVariants() {
		if candidate.rounds == maxCipherRounds {
			v = candidate
			break
		}
	}
	for _, size := range []struct {
		name string
		n    int
	}{{"32B", 32}, {"1MiB", 1 << 20}} {
		b.Run(size.name, func(b *testing.B) {
			r := rand.New(rand.NewSource(1))
			plain := make([]byte, size.n)
			r.Read(plain)
			owner := newOwnerKey(r)
			ct, low, high := v.encode(r, plain, owner)
			b.SetBytes(int64(size.n))
			for b.Loop() {
				v.decode(ct, owner[0], owner[1], low, high)
			}
		})
	}
}
