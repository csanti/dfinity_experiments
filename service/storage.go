package service

import (
	"github.com/dedis/kyber/sign/bls"
	"github.com/dedis/kyber/sign/tbls"
	"github.com/dedis/onet/log"
)

// roundStorage keeps tracks of all received valid blocks for a given round and
// if one has been notarized yet.
type roundStorage struct {
	c                 *Config                  // the config used to verify block signatures
	Round             int                      // the round number
	blocks            map[string]*blockStorage // all the blocks received for this round, mapped by their hash
	notarized         bool                     // set to true when at least one block is notarized for this round
	notarizedCb       NotarizationCb           // called when a block becomes notarzied for this round
	highestCb         HighestCb                // called when a new block proposal has a higher weight than previously seen
	weights           []int                    // weights of each possible block for this round
	highest           int                      // highest weight of notarized block seen so far
	maxWeightProposal int                      // maximum weight of the proposed blocks seen so far
}

type NotarizationCb func(*Block, *Notarization)
type HighestCb func(*BlockProposal)

// newRoundStorage returns a new round storage for the given round
func newRoundStorage(c *Config, round int, weights []int, notarizedCb NotarizationCb) *roundStorage {
	return &roundStorage{
		c:           c,
		Round:       round,
		blocks:      make(map[string]*blockStorage),
		notarizedCb: notarizedCb,
		weights:     weights,
	}
}

// SetHighestCallback is called when the timeout BlockTime expired and that the
// round storage can dispatch the highest proposal blocks
func (r *roundStorage) SetHighestCallback(cb HighestCb) {
	r.highestCb = cb
}

// newBlock accepts a new received block and stores it internally
// It returns an error if the signature is invalid.
func (r *roundStorage) StoreBlockProposal(p *BlockProposal) error {
	if p.Round != r.Round {
		panic("this should never happen")
	}
	hash := p.Hash()
	storage, exists := r.blocks[hash]
	if !exists {
		storage = newBlockStorage(r.c, &p.BlockHeader, p.Blob)
	}
	err := storage.AddPartialSig(p.BlockHeader.Owner, p.Partial)
	if err != nil {
		return err
	}

	// check if we can dispatch and if it's a higher weight than previous
	// proposals
	if r.highestCb != nil {
		weight := r.weights[storage.header.Owner]
		if weight > r.maxWeightProposal {
			go r.highestCb(p)
		}
	}
	return nil
}

// StoreSignatureProposal sotres the signature to the right blocks. If a block
// becomes notarized this way,m the callback is called if the block has the
// highest weight seen so far.
func (r *roundStorage) StoreSignatureProposal(s *SignatureProposal) error {
	if s.BlockHeader.Round != r.Round {
		panic("this should never happen")
	}
	h := s.BlockHeader.Hash()
	block, exists := r.blocks[h]
	if !exists {
		// first time we received something about this block
		block = newBlockStorage(r.c, &s.BlockHeader, s.Blob)
	}
	if err := block.AddPartialSig(s.Signer, s.Partial); err != nil {
		return err
	}

	// only dispatch if we haven't seen notarized block before
	if !r.notarized && block.IsNotarized() {
		block, nota, found := r.NotarizedBlock()
		if !found {
			panic("block notarized but not found ??")
		}
		r.notarized = true
		if r.weights[block.Owner] > r.highest {
			// only use callback for new highest weight ranks
			go r.notarizedCb(block, nota)
		}
	}
	return nil
}

func (r *roundStorage) Block(hash string) *blockStorage {
	b := r.blocks[hash]
	return b
}

// NotarizedBlock looks at the blocks and returns the highest weighted notarized
// block if any. It returns false if there was no notarized block.
func (r *roundStorage) NotarizedBlock() (*Block, *Notarization, bool) {
	var block *Block
	var not *Notarization
	var found bool
	for _, storage := range r.blocks {
		if !storage.IsNotarized() {
			continue
		}
		found = true
		b, n := storage.NotarizedBlock()
		weight := r.weights[b.Owner]
		if weight >= r.highest {
			block = b
			not = n
			r.highest = weight
		}
	}
	return block, not, found
}

// NotarizedBlocks returns the list of notarized blocks referencing the previous
// block denoted by its "prvHash". Returns nil if none such block.
func (r *roundStorage) NotarizedBlocks(prvHash string) []*Block {
	var blocks []*Block
	for _, storage := range r.blocks {
		if !storage.IsNotarized() {
			continue
		}
		if storage.header.PrvHash != prvHash {
			continue
		}
		b, _ := storage.NotarizedBlock()
		blocks = append(blocks, b)
	}
	return blocks
}

// SignsProposals signs all blocks that have not been signed yet
func (r *roundStorage) SignsProposals() []*SignatureProposal {
	var sigs []*SignatureProposal
	var maxWeightProposal int
	for _, storage := range r.blocks {
		if storage.Signed() {
			continue
		}
		weight := r.weights[storage.header.Owner]
		if weight > maxWeightProposal {
			maxWeightProposal = weight
		}
		sigs = append(sigs, storage.Signs())
	}
	r.maxWeightProposal = maxWeightProposal
	return sigs
}

// blockStorage stores all information regarding a particular block and the
// signatures received for this specific block. It is meant to only be used with
// roundStorage.
type blockStorage struct {
	c        *Config        // config used to recover the final signature
	header   *BlockHeader   // header representing the block
	blob     []byte         // the actual data
	finalSig []byte         // when notarization happenned
	sigs     map[int][]byte // all signatures for the blob received so far
	signed   bool           // true if this node has signed the proposal already
}

// newBlockStorage returns a new storage for this block holding on all
// signatures received so far
func newBlockStorage(c *Config, h *BlockHeader, blob []byte) *blockStorage {
	return &blockStorage{
		c:      c,
		header: h,
		blob:   blob,
		sigs:   make(map[int][]byte),
	}
}

func (b *blockStorage) Signed() bool {
	return b.signed
}

func (b *blockStorage) Signs() *SignatureProposal {
	if b.Signed() {
		panic("this should not happen")
	}

	if b.finalSig != nil {
		panic("we don't sign notarized blocks...")
	}

	sig, err := tbls.Sign(Suite, b.c.Share, []byte(b.header.Hash()))
	if err != nil {
		panic("this should not happen")
	}

	return &SignatureProposal{
		BlockHeader: *b.header,
		Blob:        b.blob,
		Signer:      b.c.Share.I,
		Partial:     sig,
	}
}

// AddPartialSig appends a new tbls signature to the list of already received signature
// for this block. It returns an error if the signature is invalid.
func (b *blockStorage) AddPartialSig(signer int, s []byte) error {
	if err := tbls.Verify(Suite, b.c.Public, []byte(b.header.Hash()), s); err != nil {
		return err
	}
	_, exists := b.sigs[signer]
	if exists {
		return nil
	}
	b.sigs[signer] = s
	return nil
}

// setFinalSig is used when a final signature on a next block has been generated
// but withtout the previous block being notarized locally => the next block has
// the full notarization of the b block.
func (b *blockStorage) SetFinalSig(sig []byte) error {
	if err := bls.Verify(Suite, b.c.Public.Commit(), []byte(b.header.Hash()), sig); err != nil {
		return err
	}
	b.finalSig = sig
	return nil
}

// NotarizedBlock returns the block notarized if possible otherwise nil.
func (b *blockStorage) NotarizedBlock() (*Block, *Notarization) {
	if b.finalSig != nil {
		return &Block{
				BlockHeader: *b.header,
				Blob:        b.blob,
			}, &Notarization{
				Hash:      b.header.Hash(),
				Signature: b.finalSig,
			}
	}

	if len(b.sigs) < b.c.Threshold {
		panic("this should never happen since we call it 'safely'")
	}

	arr := make([][]byte, 0, b.c.Threshold)
	for _, val := range b.sigs {
		arr = append(arr, val)
	}

	var err error
	signature, err := tbls.Recover(Suite, b.c.Public, []byte(b.header.Hash()), arr, b.c.Threshold, b.c.N)
	if err != nil {
		log.Lvl2("recovering of block", b.header.Hash(), " signatures failed:", err)
		return nil, nil
	}

	return &Block{
			BlockHeader: *b.header,
			Blob:        b.blob,
		}, &Notarization{
			Hash:      b.header.Hash(),
			Signature: signature,
		}
}

// IsNotarized looks if there are enough partial signatures. If so, it tries to recover
// the full signature and returns true in case of success. If there are not
// enough signatures, it returns false.
func (b *blockStorage) IsNotarized() bool {
	if b.finalSig != nil {
		return true
	}

	if len(b.sigs) < b.c.Threshold {
		return false
	}
	return true
}
