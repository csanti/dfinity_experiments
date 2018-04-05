package service

import (
	"github.com/dedis/kyber/share"
	"github.com/dedis/onet"
	"github.com/dedis/onet/network"
)

// Config holds all the parameters for the consensus protocol
type Config struct {
	Seed         int64        // seed to construct the PRNG => random beacon
	Roster       *onet.Roster // participants
	Index        int          // index of the node receiving this config
	N            int          // length of participants
	BeaconNb     int          // how many nodes for the randomness beacon ==> 1 for the moment
	BlockMakerNb int          // how many nodes for the block makers
	NotarizerNb  int          // how many notarizers in the simulation

	Public       *share.PubPoly  // public polynomial
	Share        *share.PriShare // private share
	Threshold    int             // threshold of the threshold sharing scheme
	BlockSize    int             // the size of the block in bytes
	BlockTime    int             // blocktime in seconds
	FinalizeTime int             // time T to wait during finalization
}

// NotarizerNodes returns the list of notarizers for the given config
func (c *Config) NotarizerNodes() []*network.ServerIdentity {
	start := c.BeaconNb + c.BlockMakerNb
	return c.Roster.List[start:]
}

// BlockMakerNodes returns the list of block makers identities
func (c *Config) BlockMakerNodes() []*network.ServerIdentity {
	start := c.BeaconNb
	end := c.BeaconNb + c.BlockMakerNb
	return c.Roster.List[start:end]
}

func (c *Config) IsBeacon(i int) bool {
	if i < c.BeaconNb {
		return true
	}
	return false
}

func (c *Config) IsBlockMaker(i int) bool {
	if i >= c.BeaconNb && i < c.BeaconNb+c.BlockMakerNb {
		return true
	}
	return false
}

func (c *Config) IsNotarizer(i int) bool {
	start := c.BeaconNb + c.BlockMakerNb
	if i >= start {
		return true
	}
	return false
}
