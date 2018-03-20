package service

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/dedis/kyber/sign/tbls"
	"github.com/dedis/onet/log"
)

// FinalizedChain is the chain that contains only blocks that are final,i.e.
// no blocks can't get marked as dead.
type FinalizedChain struct {
	Blocks []*Block
	Weight int
	Lenght int
}

// Appends add a new block to the head of the chain
func (f *FinalizedChain) Append(b *Block, weight int) {
	f.Blocks = append(f.Blocks, b)
	f.Weight += weight
}

func (f *FinalizedChain) Head() *Block {
	return f.Blocks[len(f.Blocks)-1]
}

// MultiChain contains the multi chain structure described in the paper, with
// one part finalized and different parts for the last 3 rounds (probabilistic
// consensus). It implements the logic of the consensus. It is NOT thread safe.
type MultiChain struct {
	sync.Mutex
	// config holding all crypto + simulation parameters
	c *Config
	// the finalized chain
	final *FinalizedChain
	// round number of the local head of the chain
	head int
	// blocks pending to be notarized / marked
	lastRounds map[int]*roundStorage
	// the simulated randomness beacon
	beacon *Beacon
	// blocks stored because they references a future round
	// round number => blocks
	tmpBlocks map[int][]*BlockProposal
	// sigs stored because they references a future block
	// round number => signatures
	tmpSigs map[int][]*SignatureProposal
	// broadcast function to send packets out
	broadcast BroadcastFn
}

type BroadcastFn func(interface{})

// NewMultiChain returns a fresh multi chain
func NewMultiChain(c *Config, broadcast BroadcastFn) *MultiChain {
	final := &FinalizedChain{}
	// set genesis block
	final.Append(GenesisBlock, 0)
	return &MultiChain{
		c:          c,
		beacon:     NewBeacon(c.Seed, c.Roster.List),
		final:      final,
		lastRounds: make(map[int]*roundStorage),
		tmpBlocks:  make(map[int][]*BlockProposal),
		tmpSigs:    make(map[int][]*SignatureProposal),
		broadcast:  broadcast,
	}
}

// ProcessBlockProposal looks if the block is for the current round. If so, it
// process it along with the other blocks of the same round. If it is an
// previous block, we discard it. If it is a future block, we save it
// temporarily.
func (m *MultiChain) ProcessBlockProposal(p *BlockProposal) {
	m.Lock()
	defer m.Unlock()
	currRound := m.beacon.Round()
	if p.Round < currRound {
		log.Lvl3("chain received out-of-round block")
		return
	}

	if p.Round > currRound {
		log.Lvl2("received future block -> storing temporarily")
		m.tmpBlocks[p.Round] = append(m.tmpBlocks[p.Round], p)
		return
	}

	round, exists := m.lastRounds[p.Round]
	if !exists {
		panic("same round but not round storage? impossible!")
	}

	if err := round.StoreBlockProposal(p); err != nil {
		log.Lvl2("Invalid signature over new block")
		return
	}
}

// ProcessSignatureProposal process a node's signature over a block.
func (m *MultiChain) ProcessSignatureProposal(s *SignatureProposal) {
	m.Lock()
	defer m.Unlock()
	currRound := m.beacon.Round()
	if s.Round < currRound-1 {
		log.Lvl3("chain received out-of-round signature proposal")
		return
	}

	if s.Round > currRound {
		log.Lvl2("received future signature proposal -> storing temporarily")
		m.tmpSigs[s.Round] = append(m.tmpSigs[s.Round], s)
		return
	}

	round, exists := m.lastRounds[s.Round]
	if !exists {
		panic("received signature proposal without a round storage associated...")
	}

	if err := round.StoreSignatureProposal(s); err != nil {
		log.Lvl2("err storing signature proposal: ", err)
	}
}

// NewRound does the following:
// gets the new permutation
// creates and send a new block
// wait for BlockTime and then looks for the blocks of the round as long as one
// is not notarized yet
func (m *MultiChain) NewRound() {
	m.Lock()
	defer m.Unlock()
	var previousRound = m.beacon.Round()
	m.beacon.Next()
	var currentRound = m.beacon.Round()
	blob := make([]byte, m.c.BlockSize, m.c.BlockSize)
	rand.Read(blob)
	root := rootHash(blob)

	var previousBlock *Block
	var previousSig []byte
	if previousRound == 0 {
		// i.e. we were at the genesis block genesis block
		previousBlock = GenesisBlock
		// take the same for the genesis block
		previousSig = previousBlock.PrvSig
	} else {
		// take the highest weighted notarized block
		storage, exists := m.lastRounds[previousRound]
		if !exists {
			panic("this should never happen")
		}
		_, notarization, found := storage.NotarizedBlock()
		if !found {
			panic("moving to next round without notarized block? impossible")
		}
		previousSig = notarization.Signature
	}

	// create the header and signature
	header := &BlockHeader{
		Round:   currentRound,
		Owner:   m.c.Share.I,
		Root:    root,
		PrvHash: previousBlock.Hash(),
		PrvSig:  previousSig,
	}
	// create the storage for the new round
	weights := m.beacon.Weights(currentRound)
	newStorage := newRoundStorage(m.c, currentRound, weights, m.notarizedCb)
	m.lastRounds[currentRound] = newStorage

	// create our block proposal with signature
	signature, err := tbls.Sign(Suite, m.c.Share, []byte(header.Hash()))
	if err != nil {
		panic("this should never happen")
	}

	b := &BlockProposal{
		BlockHeader: *header,
		Blob:        blob,
		Partial:     signature,
	}
	if err := newStorage.StoreBlockProposal(b); err != nil {
		panic("err adding our own proposal: " + err.Error())
	}

	// check all temp blocks and sigs
	if tmpBlocks, exists := m.tmpBlocks[currentRound]; exists {
		for _, b := range tmpBlocks {
			newStorage.StoreBlockProposal(b)
		}
	}
	if tmpSigs, exists := m.tmpSigs[currentRound]; exists {
		for _, s := range tmpSigs {
			newStorage.StoreSignatureProposal(s)
		}
	}

	// send the block
	m.broadcast(b)

	// wait BlockTime and accept to sign
	go m.waitAndSign(newStorage)
}

// waitAndSign waits BlockTime and signs all proposals received so far.
func (m *MultiChain) waitAndSign(storage *roundStorage) {
	time.Sleep(time.Duration(m.c.BlockTime) * time.Second)
	m.Lock()
	defer m.Unlock()
	sigs := storage.SignsProposals()
	if sigs != nil {
		m.broadcast(sigs)
	}
	// set the callback and only accepts highest proposals w
	storage.SetHighestCallback(m.highestCb)
}

// highestCb gets called when a block with a highest weight have been proposed
// in a given round
func (m *MultiChain) highestCb(bp *BlockProposal) {
	m.Lock()
	defer m.Unlock()
	if bp.Round != m.beacon.Round() {
		return
	}
	// create our block proposal with signature
	signature, err := tbls.Sign(Suite, m.c.Share, []byte(bp.BlockHeader.Hash()))
	if err != nil {
		panic("this should never happen")
	}

	sp := &SignatureProposal{
		BlockHeader: bp.BlockHeader,
		Blob:        bp.Blob,
		Signer:      m.c.Share.I,
		Partial:     signature,
	}
	m.broadcast(sp)
}

// notarizedCb checks if the notarized block is for the current round, (it
// should always be), if the block references a correct previous block. If so,
// it starts the next round.
func (m *MultiChain) notarizedCb(b *Block, n *Notarization) {
	m.Lock()
	defer m.Unlock()
	if b.Round != m.beacon.Round() {
		panic("this should never happen")
	}

	var correctlyReferenced bool
	if b.Round-1 == 0 {
		// genesis block
		// no need for signature check in that case
		if b.PrvHash == GenesisBlock.Hash() {
			correctlyReferenced = true
		}
	} else {
		lastRound, exists := m.lastRounds[b.Round-1]
		if !exists {
			panic("we should always have the last round of new notarized block")
		}
		blockStorage := lastRound.Block(b.PrvHash)
		if blockStorage == nil {
			panic("notarized block computed over a non existent previous block")
		}
		if !blockStorage.IsNotarized() {
			if err := blockStorage.SetFinalSig(b.BlockHeader.PrvSig); err != nil {
				log.Lvl2("invalid signature for previous block reference")
				return
			}
		}
		correctlyReferenced = true
	}

	if !correctlyReferenced {
		return
	}

	// all is fine, we go to new round
	go m.NewRound()
	// we call finalize for round-1 in T time
	go m.waitAndFinalize(m.beacon.Round() - 1)
}

// waitAndFinalize wait T time, and appends to the finalized chain the heaviest
// block to the chain
func (m *MultiChain) waitAndFinalize(round int) {
	time.Sleep(time.Duration(m.c.FinalizeTime) * time.Second)
	m.Lock()
	defer m.Unlock()
	if round < 2 {
		// can't finalizes the genesis + one round, we need one more round
		return
	}
	currRound, exists := m.lastRounds[round]
	if !exists {
		panic("this should never happen")
	}
	previousRound, exists := m.lastRounds[round-1]
	if !exists {
		panic("this should never happen")
	}

	// search all blocks that references the head of the finalized chain
	prvBlocks := previousRound.NotarizedBlocks(m.final.Head().Hash())
	prvWeights := m.beacon.Weights(round - 1)
	currWeight := m.beacon.Weights(round)

	// compute all possible chains going from finalizedChain + prvBlocks + roundBlocks
	var maxWeight = m.final.Weight
	var selectedPrvBlock *Block
	var selectedBlockWeight int
	for _, prvBlock := range prvBlocks {
		var prvWeight = maxWeight + prvWeights[prvBlock.Owner]
		// all the blocks at round that points to a block at previous round
		currBlocks := currRound.NotarizedBlocks(prvBlock.Hash())
		// compute all potential chain weight
		for _, currBlock := range currBlocks {
			var currWeight = prvWeight + currWeight[currBlock.Owner]
			if currWeight < maxWeight {
				continue
			}
			// the weight is the maximum found so far
			maxWeight = currWeight
			// save the block and its associated weight
			selectedPrvBlock = prvBlock
			selectedBlockWeight = prvWeights[prvBlock.Owner]
		}
	}

	if selectedPrvBlock == nil {
		panic("that's bad, consensus is not working")
	}
	log.Lvl1("Node appended for round", selectedPrvBlock.Round, " block ", selectedPrvBlock.Hash())
	m.final.Append(selectedPrvBlock, selectedBlockWeight)
	// delete the previous round since it's of no use anymore
	delete(m.lastRounds, round-1)
}
