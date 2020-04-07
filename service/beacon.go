package service

import (
	"math/rand"
	"sync"

	"github.com/csanti/onet"
	"github.com/csanti/onet/log"
	"github.com/csanti/onet/network"
)

const seed = 1234567890
const BeaconServiceName = "beacon"

// Beacon produces a new random value every new round and broadcasts it
type Beacon struct {
	sync.Mutex
	*onet.ServiceProcessor
	c         *Config
	r         *rand.Rand
	round     int
	broadcast BroadcastFn
	fin       *Finalizer
}

// NewBeaconProcess returns a fresh Beacon process
func NewBeaconProcess(c *onet.Context, conf *Config, b BroadcastFn) *Beacon {
	return &Beacon{
		c:                conf,
		r:                rand.New(rand.NewSource(seed)),
		ServiceProcessor: onet.NewServiceProcessor(c),
		broadcast:        b,
	}
}

// Process analyzes incoming packets
func (b *Beacon) Process(e *network.Envelope) {
	b.Lock()
	defer b.Unlock()
	switch inner := e.Msg.(type) {
	case *BeaconPacket:
		// special case when we have different randomness beacon and only one is
		// starting, or when one beacon is late behind
		b.round++
	case *NotarizedBlock:
		b.NewRound(inner.Round)
	default:
		panic("beacon: should not happen")
	}
}

// NewRound generates the new randomness and sends its to all other nodes
func (b *Beacon) NewRound(r int) {
	if r != b.round {
		log.Lvl2("beacon service received different round")
		return
	}
	b.round++
	nextRandomness := b.r.Int63()
	packet := &BeaconPacket{
		Round:      b.round,
		Randomness: nextRandomness,
	}
	for _, si := range append(b.c.NotarizerNodes(), b.c.BlockMakerNodes()...) {
		go b.SendRaw(si, packet)
	}
	log.Lvl1("beacon: new round started ", b.round)
}

// Start runs the first round
func (b *Beacon) Start() {
	b.NewRound(0)
}

// Permutation returns the mapping from oroginal index to the new index in order
// to compute the ranking
func Permutation(n int, randomness int64) map[int]int {
	perms := rand.New(rand.NewSource(randomness)).Perm(n)
	maps := make(map[int]int)
	for i := 0; i < n; i++ {
		maps[i] = perms[i]
	}
	return maps
}

// all weights for all possible block for a round. The weights are computed as
// len(participants) - newIdex for each owner so we avoid float64 computations.
func Weights(n int, randomness int64) []int {
	perm := Permutation(n, randomness)
	weights := make([]int, n)
	for i := 0; i < n; i++ {
		newIndex := perm[i]
		weights[i] = newIndex + 1
	}
	return weights
}
