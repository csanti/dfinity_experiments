package service

import (
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/onet"
	"github.com/dedis/onet/network"
)

var Suite = bn256.NewSuite()
var g2 = Suite.G2()
var dfinityName = "dfinity"

func init() {
	onet.RegisterNewService(dfinityName, NewDfinityService)
}

// dfinity service is either a beacon a notarizer or a block maker
type dfinity struct {
	*onet.ServiceProcessor
	context *onet.Context
	c       *Config
	beacon  *Beacon
	not     *Notarizer
	bm      *BlockMaker
}

// NewDfinityService
func NewDfinityService(c *onet.Context) (onet.Service, error) {
	d := &dfinity{
		context:          c,
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	c.RegisterProcessor(d, BlockProposalType)
	c.RegisterProcessor(d, NotarizedBlockType)
	c.RegisterProcessor(d, SignatureProposalType)
	c.RegisterProcessor(d, BeaconType)
	return d, nil
}

func (d *dfinity) SetConfig(c *Config) {
	d.c = c
	if c.IsBeacon(c.Index) {
		d.beacon = NewBeaconProcess(d.context, c, d.broadcast)
		d.beacon.Start()
	} else if c.IsBlockMaker(c.Index) {
		d.bm = NewBlockMakerProcess(d.context, c, d.broadcast)
	} else if c.IsNotarizer(c.Index) {
		d.not = NewNotarizerProcess(d.context, c, d.broadcast)
	}
}

// Process
func (d *dfinity) Process(e *network.Envelope) {
	switch e.Msg.(type) {
	case *BeaconPacket:
		if d.not != nil {
			d.not.Process(e)
		} else if d.bm != nil {
			d.bm.Process(e)
		}
	case *BlockProposal:
		if d.not != nil {
			d.not.Process(e)
		}
	case *SignatureProposal:
		if d.not != nil {
			d.not.Process(e)
		}
	case *NotarizedBlock:
		if d.beacon != nil {
			d.beacon.Process(e)
		} else if d.bm != nil {
			d.bm.Process(e)
		}
	}
}

type BroadcastFn func(sis []*network.ServerIdentity, msg interface{})

func (d *dfinity) broadcast(sis []*network.ServerIdentity, msg interface{}) {
	for _, si := range sis {
		if d.ServerIdentity().Equal(si) {
			continue
		}
		if err := d.ServiceProcessor.SendRaw(si, msg); err != nil {
			panic(err)
		}
	}
}
