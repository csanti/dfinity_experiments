package service

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/csanti/onet"
	"github.com/csanti/onet/log"
	"github.com/csanti/onet/network"
)

// BlockMaker creates new blocks for each round
type BlockMaker struct {
	sync.Mutex
	*onet.ServiceProcessor
	c         *Config
	chain     *Chain
	fin       *Finalizer
	broadcast BroadcastFn
	*sync.Cond
	highestRound int
}

// NewBlockMakerProcess returns a fresh block maker
func NewBlockMakerProcess(c *onet.Context, conf *Config, b BroadcastFn) *BlockMaker {
	chain := new(Chain)
	return &BlockMaker{
		c:                conf,
		ServiceProcessor: onet.NewServiceProcessor(c),
		fin:              NewFinalizer(conf, chain, nil),
		chain:            chain,
		broadcast:        b,
		Cond:             sync.NewCond(new(sync.Mutex)),
	}
}

// Process analyzes every incoming packet
func (b *BlockMaker) Process(e *network.Envelope) {
	b.Lock()
	defer b.Unlock()
	switch inner := e.Msg.(type) {
	case *BeaconPacket:
		go b.NewRound(inner)
	case *NotarizedBlock:
		log.Lvl1("BlockMaker received notarized block for round", inner.Round)
		b.fin.Store(inner)
		b.Cond.Broadcast()
	}
}

// NewRound finds the highest priority chain's head block
// and create a new block on top of it that gets broadcasted.
func (b *BlockMaker) NewRound(p *BeaconPacket) {
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()
	for b.fin.HighestRound() < p.Round-1 {
		log.Lvl1("blockmaker: waiting highest round go to ", p.Round-1)
		b.Cond.Wait()
	}
	newRound := p.Round
	oldBlock, err := b.fin.HighestChainHead(newRound - 1)
	if err != nil {
		fmt.Println(b.fin.notarized)
		panic(err)
	}
	//blob := []byte(fmt.Sprintf("block data round %d owner %d", p.Round, b.c.Index))
	blob := make([]byte, b.c.BlockSize)
	rand.Read(blob)

	hash := rootHash(blob)
	header := BlockHeader{
		Round:      newRound,
		Owner:      b.c.Index - b.c.BeaconNb,
		Root:       hash,
		Randomness: p.Randomness,
		PrvHash:    oldBlock.Block.BlockHeader.Hash(),
		PrvSig:     oldBlock.Notarization.Signature,
	}
	blockProposal := &BlockProposal{
		BlockHeader: header,
		Blob:        blob,
	}
	go b.broadcast(b.c.NotarizerNodes(), blockProposal)

	weights := Weights(b.c.BlockMakerNb, p.Randomness)
	log.Lvl1("blockmaker broadcasted block (weight", weights[header.Owner], ") ", header.Hash(), "on top of ", oldBlock.BlockHeader.Hash())
}
