package service

import (
	"fmt"
	"sync"
	"time"
)

// Chain is the chain that contains only blocks that are final,i.e.
// no blocks can't get marked as dead.
type Chain struct {
	sync.Mutex
	all    []*Block
	last   *Block
	length int
}

// Appends add a new block to the head of the chain
func (f *Chain) Append(b *Block) {
	f.Lock()
	defer f.Unlock()
	if f.length > 0 && b.BlockHeader.PrvHash != f.last.BlockHeader.Hash() {
		panic("that should never happen")
	}
	f.last = b
	f.length++

	f.all = append(f.all, b)
}

// length returns the length of the finalized chain
func (f *Chain) Length() int {
	f.Lock()
	defer f.Unlock()
	return f.length
}

//
func (f *Chain) Head() *Block {
	f.Lock()
	defer f.Unlock()
	return f.last
}

func (f *Chain) String() string {
	s := fmt.Sprintf("chain: length = %d\n", f.length)
	for i, b := range f.all {
		s += fmt.Sprintf("\u21b3 round %d: %s", b.BlockHeader.Round, b.BlockHeader.Hash())
		if i > 0 {
			if f.all[i-1].BlockHeader.Hash() == b.BlockHeader.PrvHash {
				s += fmt.Sprintf("  \u2713")
			} else {
				s += fmt.Sprintf("  wrong previous hash %s", b.BlockHeader.PrvHash)
			}
		} else {
			s += "  \u2713"
		}
		s += "\n"
	}
	return s
}

// Finalizer holds the logic of the finalizing algorithm
type Finalizer struct {
	sync.Mutex
	// general config
	c *Config
	// final chain
	chain *Chain
	// list of notarized blocks
	notarized map[int][]*NotarizedBlock
	// current round
	round int
	// done callback
	done func(int)
}

// NewFinalizer returns a fresh new finalizer
// done is the callback called when the finalizing call has finishedi, i.e. after
// sleeping T time and purging the chain.
func NewFinalizer(c *Config, chain *Chain, done func(int)) *Finalizer {
	f := &Finalizer{
		c:         c,
		chain:     chain,
		notarized: make(map[int][]*NotarizedBlock),
		done:      done,
		round:     1,
	}
	f.notarized[0] = []*NotarizedBlock{&NotarizedBlock{
		Block: GenesisBlock,
		Notarization: &Notarization{
			Hash:      GenesisBlock.BlockHeader.Hash(),
			Signature: []byte("who are you old fool"),
		},
	}}
	return f
}

// Store process the given notarized block and fire up the finalize routine if
// needed
func (f *Finalizer) Store(n *NotarizedBlock) {
	f.Lock()
	defer f.Unlock()
	if n.Round < f.round {
		return
	}
	hash := n.Block.Hash()
	_, before := f.notarized[f.round]
	key := n.Block.BlockHeader.Round
	for _, b := range f.notarized[key] {
		if b.Block.Hash() == hash {
			// don't store twice the same block
			return
		}
	}
	f.notarized[key] = append(f.notarized[key], n)
	//log.Lvl1("Finalizer: not. block round", n.Round, " before?", before, " => key", key, " => ", f.notarized[key])
	if !before && key == f.round {
		// first time we see a notarized block for the current round
		go f.finalize(f.round)
	}
}

// HighestRound returns the highest round this finalizer has seen
// so far
func (f *Finalizer) HighestRound() int {
	f.Lock()
	defer f.Unlock()
	var max int
	for round := range f.notarized {
		if max < round {
			max = round
		}
	}
	return max
}

// start from the blocks at round "round",
// for each of these, tracks all the blocks referenced that points to the
// head of the chain, so all "valid chains"
// pick the highest chains amongst these.
func (f *Finalizer) HighestChainHead(round int) (*NotarizedBlock, error) {
	f.Lock()
	defer f.Unlock()
	if round == 0 {
		return f.notarized[0][0], nil
	}

	blocks, exists := f.notarized[round]
	if !exists {
		return nil, fmt.Errorf("no blocks exists for this round %d", round)
	}

	endRound := f.chain.Length()
	startRound := round
	//var chainHash string
	if b := f.chain.Head(); b != nil {
		//chainHash = b.Hash()
	} else {
		// XXXf ind the highest chain  in the non notarized block
	}
	allWeights := make(map[int][]int, startRound-endRound)
	// returns the weight for a given block
	getWeight := func(block *NotarizedBlock) int {
		weights, exists := allWeights[block.Round]
		if !exists {
			weights = Weights(f.c.BlockMakerNb, block.Randomness)
			allWeights[block.Round] = weights
		}
		//fmt.Println("weights: ", weights, " ==> owner: ", block.Owner)
		return weights[block.Owner]
	}
	// max weight to block returns the maximum chain weight found going back to the
	// finalized chain
	var maxWeightToBlock func(block *NotarizedBlock) int
	maxWeightToBlock = func(block *NotarizedBlock) int {
		weight := getWeight(block)
		// we're at the last block before the finalized chain
		if block.Round-1 == endRound {
			// but this block does not reference this head of the finalized
			// chain. chainHash != "" needed for the first two blocks that
			// haven't yet made it in the finalized chain
			/*if chainHash != "" && block.PrvHash != chainHash {*/

			//return 0
			/*}*/
			// so returns its weight
			return weight
		}

		hash := block.Block.Hash()
		prevBlocks, exists := f.notarized[block.Round-1]
		if exists {
			// should never happen though
			return weight
		}
		var maxPrvWeight int
		for _, b := range prevBlocks {
			// only take blocks that references the given one
			if b.BlockHeader.Hash() != hash {
				continue
			}
			// compute weights starting from this previous block
			prvWeight := maxWeightToBlock(b)
			if maxPrvWeight < prvWeight {
				maxPrvWeight = prvWeight
			}
		}
		return maxPrvWeight + weight
	}
	var maximum int
	var maxBlock *NotarizedBlock
	for _, b := range blocks {
		chainWeight := maxWeightToBlock(b)
		if maximum < chainWeight {
			maximum = chainWeight
			maxBlock = b
		}
	}
	if maxBlock == nil {
		return nil, fmt.Errorf("no max block found for given round %d", round)
	}
	return maxBlock, nil
}

// finalizes runs the finalization algorithm for the given round
func (f *Finalizer) finalize(round int) {
	time.Sleep(time.Duration(f.c.FinalizeTime) * time.Millisecond)
	f.Lock()
	defer func() {
		if f.done != nil {
			f.done(round)
		}
	}()
	defer f.Unlock()
	if round-1 <= 0 {
		f.round++
		return
	}
	f.purge(round - 1)
	// XXX DO the whole r' R* once we're sure
	// XXX For the moment take the block at round r-2
	b := f.notarized[round-2][0]
	f.chain.Append(b.Block)
	delete(f.notarized, round-2)
	f.round++
}

// purge is the recursive call to the purge the chain
// ONLY CALLED WHEN CALLER HAVE THE LOCK
// XXX Not doing any recursive stuff for the moment
func (f *Finalizer) purge(start int) {
	prevBlocks, exists := f.notarized[start-1]
	if !exists {
		fmt.Println("purge: start", start, " => f.notarized", f.notarized)
		panic("that should not happen")
	}
	if len(prevBlocks) <= 1 {
		return
	}
	startBlocks, exists := f.notarized[start]
	if !exists {
		panic("that should not happen")
	}

	var referencedIdx []int
	for i := range prevBlocks {
		ib := prevBlocks[i]
		ihash := ib.Block.BlockHeader.Hash()
		var referenced bool
		for _, jb := range startBlocks {
			// check if a previous block is referenced from a block in the next round
			if ihash == jb.Block.BlockHeader.PrvHash {
				referenced = true
				break
			}
		}
		if referenced {
			referencedIdx = append(referencedIdx, i)
		}
	}
	// there should be only one left
	if len(referencedIdx) > 1 {
		panic("that should not happen")
	}
	finalizedBlock := prevBlocks[referencedIdx[0]]
	delete(f.notarized, start-1)
	f.notarized[start-1] = []*NotarizedBlock{finalizedBlock}
}
