package service

import (
	"math/rand"

	"github.com/dedis/onet/network"
)

// Beacon is a simulation of the randomness beacon from the paper. It is simply
// a local PNRG initiated with a known seed so every participants generate the
// same "random" permutations.
type Beacon struct {
	seed      int64
	currRound int
	state     *rand.Rand
	perms     map[int]map[int]int
	n         int // number of participants
}

// NewBeacon returns a new beacon out of the given seed and the original list of
// participants
func NewBeacon(seed int64, list []*network.ServerIdentity) *Beacon {
	b := &Beacon{
		seed:      seed,
		currRound: 0,
		state:     rand.New(rand.NewSource(seed)),
		perms:     make(map[int]map[int]int),
		n:         len(list),
	}
	return b
}

// Round returns the current round where this beacon is
func (b *Beacon) Round() int {
	return b.currRound
}

// Next moves the beacon to the next round and returns the permutation for the
// new round. The permutation is the mapping between the original index and the
// new index for this round for each participants
func (b *Beacon) Next() map[int]int {
	b.currRound++
	return b.Perm(b.currRound)
}

// Perm returns the permutation of the list of nodes for a given round
func (b *Beacon) Perm(round int) map[int]int {
	perm, exists := b.perms[round]
	if !exists {
		if round < b.currRound {
			panic("this should never happen")
		}
		if round > b.currRound+1 {
			panic("nodes should have 1 round maximum difference")
		}
		b.perms[round+1] = make(map[int]int)
		for i, v := range b.state.Perm(len(perm)) {
			b.perms[round+1][v] = i
		}
		perm = b.perms[round+1]
	}
	return perm
}

// Weights computes the weights of the blocks during a given round. It returns
// all weights for all possible block for a round. The weights are computed as
// len(participants) - newIdex for each owner so we avoid float64 computations.
func (b *Beacon) Weights(round int) []int {
	perm, exists := b.perms[round]
	if !exists {
		perm = b.Perm(round)
	}
	weights := make([]int, b.n)
	for i := 0; i < b.n; i++ {
		newIndex := perm[i]
		weights[i] = b.n - newIndex
	}
	return weights
}
