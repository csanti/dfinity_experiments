package service

import (
	"go.dedis.ch/kyber/pairing/bn256"
	"github.com/csanti/onet"
	"github.com/csanti/onet/network"
)

var Suite = bn256.NewSuite()
var G2 = Suite.G2()
var Name = "dfinity"

func init() {
	onet.RegisterNewService(Name, NewDfinityService)
}

// Dfinity service is either a beacon a notarizer or a block maker
type Dfinity struct {
	*onet.ServiceProcessor
	context *onet.Context
	c       *Config
	beacon  *Beacon
	not     *Notarizer
	bm      *BlockMaker
	fin     *Finalizer
}

// NewDfinityService
func NewDfinityService(c *onet.Context) (onet.Service, error) {
	d := &Dfinity{
		context:          c,
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	c.RegisterProcessor(d, ConfigType)
	c.RegisterProcessor(d, BlockProposalType)
	c.RegisterProcessor(d, NotarizedBlockType)
	c.RegisterProcessor(d, SignatureProposalType)
	c.RegisterProcessor(d, BeaconType)
	return d, nil
}

func (d *Dfinity) SetConfig(c *Config) {
	d.c = c
	if c.IsBeacon(c.Index) {
		d.beacon = NewBeaconProcess(d.context, c, d.broadcast)
	} else if c.IsBlockMaker(c.Index) {
		d.bm = NewBlockMakerProcess(d.context, c, d.broadcast)
	} else if c.IsNotarizer(c.Index) {
		d.not = NewNotarizerProcess(d.context, c, d.broadcast)
	}
}

func (d *Dfinity) AttachCallback(fn func(int)) {
	chain := new(Chain)
	d.fin = NewFinalizer(d.c, chain, fn)
}

func (d *Dfinity) Start() {
	if d.beacon != nil {
		d.beacon.Start()
	} else {
		panic("that should not happen")
	}
}

// Process
func (d *Dfinity) Process(e *network.Envelope) {
	switch inner := e.Msg.(type) {
	case *Config:
		d.SetConfig(inner)
	case *BeaconPacket:
		if d.not != nil {
			d.not.Process(e)
		} else if d.bm != nil {
			d.bm.Process(e)
		} else if d.beacon != nil {
			d.beacon.Process(e)
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
		if d.fin != nil {
			d.fin.Store(inner)
		}
	}
}

type BroadcastFn func(sis []*network.ServerIdentity, msg interface{})

func (d *Dfinity) broadcast(sis []*network.ServerIdentity, msg interface{}) {
	for _, si := range sis {
		if d.ServerIdentity().Equal(si) {
			continue
		}
		if err := d.ServiceProcessor.SendRaw(si, msg); err != nil {
			panic(err)
		}
	}
}
