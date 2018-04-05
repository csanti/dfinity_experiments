package service

import (
	"github.com/dedis/kyber/sign/tbls"
	"github.com/dedis/onet/log"
)

// roundStorage keeps tracks of all received valid blocks for a given round and
// if one has been notarized yet.
type roundStorage struct {
	c       *Config                      // the config used to verify block signatures
	Round   int                          // the round number
	blocks  map[string]*blockStorage     // round blocks mapped from their hash
	tmpSigs map[int][]*SignatureProposal // all tmp signatures

	randomness int64
	// max weight seen so far for notarized blocks
	maxWeightNotarized int
	// maximum notarized block seen so far for this round
	maxNotarized *NotarizedBlock
	// max weight seen so far for signature proposal
	maxWeightSig int
	// weights for this round
	weights []int
	// notarized blocks seen this round
	notarizeds []*NotarizedBlock
	// the finalizer
	finalizer *Finalizer
}

// newRoundStorage returns a new round storage for the given round
func newRoundStorage(c *Config, round int, randomness int64, f *Finalizer) *roundStorage {
	return &roundStorage{
		c:                  c,
		Round:              round,
		blocks:             make(map[string]*blockStorage),
		tmpSigs:            make(map[int][]*SignatureProposal),
		randomness:         randomness,
		weights:            Weights(c.BlockMakerNb, randomness),
		finalizer:          f,
		maxWeightNotarized: -1,
		maxWeightSig:       -1,
	}
}

// StoreBlockProposal stores a block proposal
func (r *roundStorage) StoreBlockProposal(p *BlockProposal) {
	if p.Round != r.Round {
		panic("this should never happen")
	}
	hash := p.Hash()
	storage, exists := r.blocks[hash]
	if !exists {
		b := Block(*p)
		storage = newBlockStorage(r.c, &b)
		r.blocks[hash] = storage
		return
	}
}

// StoreSignatureProposal sotres the signature to the right blocks. If a block
// becomes notarized this way, it returns a NotarizedBlock. If the signature
// referes to a first we never signed /i.e. we did not know/, it returns a
// signature proposal to broadcast to the notarizer.
func (r *roundStorage) StoreSignatureProposal(s *SignatureProposal) {
	if s.BlockHeader.Round != r.Round {
		panic("this should never happen")
	}
	h := s.BlockHeader.Hash()
	block, exists := r.blocks[h]
	if !exists {
		// first time we received something about this block
		// so we sign it
		block = newBlockStorage(r.c, s.Block)
		r.blocks[h] = block
		// it can't be notarized locally if its the first time we see this block
		return
	}

	notarized, err := block.AddPartialSig(s.Partial)
	if err != nil {
		log.Lvl2("signature error block: ", err)
		return
	}
	if notarized != nil {
		r.StoreNotarizedBlock(notarized)
	}
}

// StoreNotarizedBlock stores the notarization for future retrieval
func (r *roundStorage) StoreNotarizedBlock(n *NotarizedBlock) {
	r.notarizeds = append(r.notarizeds, n)
	r.finalizer.Store(n)
}

// HighestNotarizedBlock returns the highest notarized block seen so far. If
// called twice without any new inputs, it will return nil. i.e. it saves the
// last highest notarized block seen so far and only returns highest if present
// during further calls.
func (r *roundStorage) HighestNotarizedBlock() *NotarizedBlock {
	var maxWeight = r.maxWeightNotarized
	var maxBlock *NotarizedBlock
	for _, n := range r.notarizeds {
		w := r.weights[n.Block.BlockHeader.Owner]
		if maxWeight < w {
			maxWeight = w
			maxBlock = n
		}
	}
	r.maxWeightNotarized = maxWeight
	r.maxNotarized = maxBlock
	return maxBlock
}

// isNotarized returns true if this round has seen a notarized block
func (r *roundStorage) IsNotarized() bool {
	return len(r.notarizeds) > 0
}

// HighestSignature returns the siganture for the highest block possible seen so
// far.
func (r *roundStorage) HighestSignature() *SignatureProposal {
	var maxWeight = r.maxWeightSig
	var maxSig *SignatureProposal
	for _, storage := range r.blocks {
		//fmt.Printf("block owner: %d => weights: %v\n", storage.block.Owner, r.weights)
		w := r.weights[storage.block.BlockHeader.Owner]
		//log.Lvlf1("block  %s: w: %d vs maxweight %d", storage.block.Hash(), w, maxWeight)
		if maxWeight < w {
			maxWeight = w
			maxSig = storage.SignatureProposal()
			//log.Lvl1("notarizer partially signed ", storage.block.BlockHeader.Hash())
		}
	}
	r.maxWeightSig = maxWeight
	if maxSig != nil {
		r.StoreSignatureProposal(maxSig)
	}
	return maxSig
}

// blockStorage stores all information regarding a particular block and the
// signatures received for this specific block. It is meant to only be used with
// roundStorage.
type blockStorage struct {
	c         *Config // config used to recover the final signature
	block     *Block
	finalSig  []byte         // when notarization happenned
	sigs      map[int][]byte // all signatures for the blob received so far
	notarized bool           // true if already notarized
}

// newBlockStorage returns a new storage for this block holding on all
// signatures received so far
func newBlockStorage(c *Config, b *Block) *blockStorage {
	return &blockStorage{
		c:     c,
		block: b,
		sigs:  make(map[int][]byte),
	}
}

// AddPartialSig appends a new tbls signature to the list of already received signature
// for this block. It returns an error if the signature is invalid.
func (b *blockStorage) AddPartialSig(s []byte) (*NotarizedBlock, error) {
	if b.notarized {
		// no need to store more sigs if we already have a notarized block
		return nil, nil
	}

	err := tbls.Verify(Suite, b.c.Public, []byte(b.block.BlockHeader.Hash()), s)
	if err != nil {
		return nil, err
	}

	i, err := tbls.SigShare(s).Index()
	if err != nil {
		return nil, err
	}

	b.sigs[i] = s
	// not enough yet signature to get the notarized block ready
	if len(b.sigs) < b.c.Threshold {
		return nil, nil
	}

	arr := make([][]byte, 0, b.c.Threshold)
	for _, val := range b.sigs {
		arr = append(arr, val)
	}

	hash := b.block.BlockHeader.Hash()
	signature, err := tbls.Recover(Suite, b.c.Public, []byte(hash), arr, b.c.Threshold, b.c.N)
	if err != nil {
		return nil, err
	}
	b.notarized = true
	return &NotarizedBlock{
		Block: b.block,
		Notarization: &Notarization{
			Hash:      hash,
			Signature: signature,
		},
	}, nil

}

// SignatureProposal returns the signature from this node for this block
func (b *blockStorage) SignatureProposal() *SignatureProposal {
	sig, err := tbls.Sign(Suite, b.c.Share, []byte(b.block.BlockHeader.Hash()))
	if err != nil {
		panic("this should not happen")
	}
	return &SignatureProposal{
		Block: &Block{
			BlockHeader: b.block.BlockHeader,
			Blob:        b.block.Blob,
		},
		Partial: sig,
	}
}
