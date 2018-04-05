package service

import (
	"sync"
	"time"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

// Notarizer contains the multi chain structure described in the paper, with
// one part finalized and different parts for the last 3 rounds (probabilistic
// consensus). It implements the logic of the consensus. It is NOT thread safe.
type Notarizer struct {
	*onet.ServiceProcessor
	*sync.Cond
	// config holding all crypto + simulation parameters
	c *Config
	// the finalized chain
	chain *Chain
	// the finalizer process
	finalizer *Finalizer
	// all the previous and current rounds needed
	rounds map[int]*roundStorage
	// current round number
	round int
	// temporary beacon that arrived too early
	tmpBeacon map[int]*BeaconPacket
	// future sigs
	tmpSigs map[int][]*SignatureProposal
	// future blocks
	tmpBlocks map[int][]*BlockProposal
	// future notarized blocks
	tmpNot    map[int][]*NotarizedBlock
	broadcast BroadcastFn
}

// NewMultiChain returns a fresh multi chain
func NewNotarizerProcess(c *onet.Context, conf *Config, b BroadcastFn) *Notarizer {
	chain := new(Chain)
	n := &Notarizer{
		ServiceProcessor: onet.NewServiceProcessor(c),
		chain:            chain,
		c:                conf,
		Cond:             sync.NewCond(new(sync.Mutex)),
		rounds:           make(map[int]*roundStorage),
		tmpBeacon:        make(map[int]*BeaconPacket),
		tmpBlocks:        make(map[int][]*BlockProposal),
		tmpSigs:          make(map[int][]*SignatureProposal),
		tmpNot:           make(map[int][]*NotarizedBlock),
		broadcast:        b,
	}
	n.finalizer = NewFinalizer(conf, chain, n.deleteRound)
	return n
}

// Process process incoming network packets
func (m *Notarizer) Process(e *network.Envelope) {
	m.Cond.L.Lock()
	defer m.Cond.L.Unlock()
	defer m.Cond.Broadcast()
	switch inner := e.Msg.(type) {
	case *BeaconPacket:
		m.NewRound(inner)
	case *BlockProposal:
		m.NewBlockProposal(inner)
	case *SignatureProposal:
		m.NewSignatureProposal(inner)
	case *NotarizedBlock:
		m.NewNotarizedBlock(inner)
	}
}

// NewRound starts a new notarization round
// it increase the round number and create the corresponding round storage.
func (m *Notarizer) NewRound(b *BeaconPacket) {
	if b.Round <= m.round {
		// forget about previous or current beacon
		return
	}
	if b.Round != m.round+1 {
		// stores higher beacon
		m.tmpBeacon[b.Round] = b
		return
	}
	m.round++
	m.rounds[m.round] = newRoundStorage(m.c, m.round, b.Randomness, m.finalizer)
	go m.roundLoop(b.Round)
}

func (m *Notarizer) roundLoop(round int) {
	// at the end always see if we can directly go to next step
	defer func() {
		if b, exists := m.tmpBeacon[round+1]; exists {
			m.NewRound(b)
		}
		delete(m.tmpBeacon, round+1)
	}()
	// sleep the finalization time
	time.Sleep(time.Duration(m.c.BlockTime) * time.Millisecond)
	//log.Lvl1("notarizer enters round loop for round ", round)
	// test if things look correct
	m.Cond.L.Lock()
	defer m.Cond.L.Unlock()
	roundStorage, exists := m.rounds[round]
	if !exists {
		panic("that should never happen")
	}

	var sigProposal *SignatureProposal
	// condition returns whether we should wait or quit the loop
	var condition = func() (bool, bool) {
		roundStorage, exists = m.rounds[round]
		if !exists {
			// we don't have the storage anymore
			// it has been deleted when the finalizer finished its run for this
			// round
			return false, true
		}
		if round != m.round {
			// we're at a further stage,i.e. beacon received a notarized
			// block somehow, so let's quit
			return false, true
		}
		var found bool
		for _, not := range m.tmpNot[round] {
			roundStorage.StoreNotarizedBlock(not)
			found = true
		}
		if found {
			// quit this loop since we already have a notarized block for this
			// round
			return true, true
		}
		for _, bp := range m.tmpBlocks[round] {
			roundStorage.StoreBlockProposal(bp)
		}
		for _, sigs := range m.tmpSigs[round] {
			roundStorage.StoreSignatureProposal(sigs)
		}
		if roundStorage.IsNotarized() {
			// quit this loop since we already have a notarized block for this
			// round
			return true, true
		}
		sigProposal = roundStorage.HighestSignature()
		//log.Lvl1("not. roundloop sigProposal?: ", sigProposal != nil)
		//log.Lvl1("not. round storage: ", roundStorage.blocks)
		return sigProposal != nil, false
	}

	for {
		var dataFound, mustQuit bool
		for {
			dataFound, mustQuit = condition()
			if !dataFound {
				//log.Lvl1("notarizer: waiting on new inputs...")
				m.Cond.Wait()
			} else {
				break
			}
		}

		if notarized := roundStorage.HighestNotarizedBlock(); notarized != nil {
			// a block is notarized ! quit notarizing for this round
			log.Lvl1("notarizer broadcasting notarized block round", notarized.Block.Round, ":", notarized.BlockHeader.Hash())
			go m.broadcast(m.c.Roster.List, notarized)
			return
		}

		if sigProposal == nil {
			panic("that should never happen")
		}

		//log.Lvl1("notarizer broadcasted sig proposal for ", sigProposal.BlockHeader.Hash())
		// broadcast the signature
		go m.broadcast(m.c.NotarizerNodes(), sigProposal)
		if mustQuit {
			//log.Lvl1("notarizer quit round loop at the end for round", round)
			return
		}
	}
}

// deleteRound deletes the round storage for the given round. This round number
// is given from the finalizer. It means the notarizer still can receive
// notarized block after seeing the first one of a round, but after the
// finalization routine finished, it stops receiveing new ones.
func (n *Notarizer) deleteRound(round int) {
	n.Cond.L.Lock()
	defer n.Cond.L.Unlock()
	delete(n.rounds, round)
	delete(n.tmpBeacon, round)
	delete(n.tmpSigs, round)
	delete(n.tmpBlocks, round)
	delete(n.rounds, round)
}

// NewBlockProposal stores the blockproposal internally and broadcasts a
// signature proposal in case it is the first time we see this block
func (m *Notarizer) NewBlockProposal(p *BlockProposal) {
	if p.Round < m.round {
		log.Lvl2("received too old block ")
		return
	}
	round, exists := m.rounds[p.Round]
	if !exists {
		m.tmpBlocks[p.Round] = append(m.tmpBlocks[p.Round], p)
		return
	}
	//log.Lvl1("notarizer storing new block proposal", p.BlockHeader.Hash())
	round.StoreBlockProposal(p)
}

// NewSignatureProposal process a new signature proposal. If the block
// referenced gets enough signature the final signature gets reconstructed and
// the notarizer broadcasts the notarizedblock.
func (m *Notarizer) NewSignatureProposal(s *SignatureProposal) {
	if s.Round > m.round {
		log.Lvl2("received future signature proposal -> storing temporarily")
		m.tmpSigs[s.Round] = append(m.tmpSigs[s.Round], s)
		return
	} else if s.Round < m.round {
		return
	}

	round, exists := m.rounds[s.Round]
	//log.Lvl1("notarizer storing signature proposal")
	if !exists {
		m.tmpSigs[s.Round] = append(m.tmpSigs[s.Round], s)
		//log.Lvl1("notarizer storing signature proposal IN TMP")
		return
	}
	//log.Lvl1("notarizer storing signature proposal REGULAR ")
	round.StoreSignatureProposal(s)
}

// NewNotarizedBlock saves a notarized block for future processing
func (m *Notarizer) NewNotarizedBlock(n *NotarizedBlock) {
	if n.Round > m.round {
		log.Lvl2("received future notarized block")
		m.tmpNot[n.Round] = append(m.tmpNot[n.Round], n)
		return
	}

	round, exists := m.rounds[n.Round]
	if !exists {
		log.Lvl2("too old notarized block..")
		return
	}
	round.StoreNotarizedBlock(n)
}
