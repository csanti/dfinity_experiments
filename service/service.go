package service

import (
	"sync"
	"time"

	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

const serviceName = "probconsensus"

var serviceID onet.ServiceID

// Suite is the global pairing based suite used
var Suite = bn256.NewSuite()

func init() {
	var err error
	serviceID, err = onet.RegisterNewService(serviceName, newService)
	log.ErrFatal(err)
}

// service holds up the logic for the dfinity consensus
type service struct {
	sync.Mutex
	*onet.ServiceProcessor
	Config *Config // all config parameters
	chain  *MultiChain
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	return s, nil
}

func (s *service) Process(e *network.Envelope) {
	switch inner := e.Msg.(type) {
	//case *InitPacket:
	//s.receiveInit(inner)
	case *BlockProposal:
		s.BlockProposal(e.ServerIdentity, inner)
	case *SignatureProposal:
		s.SignatureProposal(e.ServerIdentity, inner)
	default:
		panic("don't know this message. Stop bullying around.")
	}
}

func (s *service) run() {
	for {

	}
}

// BlockProposal receives a new block. It checks if the signature is valid and adds
// it to the list of blocks received for the round.
func (s *service) BlockProposal(i *network.ServerIdentity, p *BlockProposal) {
}

func (s *service) SignatureProposal(i *network.ServerIdentity, sp *SignatureProposal) {

}

// Init takes the packet containing all initialization information already. This
// is a shorthand for doing the simulation to not have to run a DKG by ourself.
func (s *service) Initializes(c *Config) {
	s.Config = c
	s.chain = NewMultiChain(c, s.Broadcast)
}

// broadcast sends the given interface to each participants in the roster
func (s *service) Broadcast(i interface{}) {
	for _, si := range s.Config.Roster.List {
		if err := s.SendRaw(si, i); err != nil {
			log.Lvl2(s.String(), "can't broadcast to ", si.Address)
		}
	}
}

// Start is used to start the "creation of block" process, to launch the
// consensus mechanism etc
func (s *service) Start() {
	begin := time.Now()
	end := time.Unix(s.Config.StartTime, 0)
	time.Sleep(end.Sub(begin))
	s.run()
}
