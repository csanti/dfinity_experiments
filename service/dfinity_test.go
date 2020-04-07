package service

import (
	"fmt"
	"testing"

	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/pairing"
	"go.dedis.ch/kyber/share"
	"go.dedis.ch/kyber/util/random"
	"github.com/csanti/onet"
	"github.com/csanti/onet/log"
)

type networkSuite struct {
	kyber.Group
	pairing.Suite
}

func newNetworkSuite() *networkSuite {
	return &networkSuite{
		Group: Suite.G2(),
		Suite: Suite,
	}
}

func TestDfinity(t *testing.T) {
	suite := newNetworkSuite()
	test := onet.NewTCPTest(suite)
	defer test.CloseAll()

	n := 6
	servers, roster, _ := test.GenTree(n, true)
	beaconNb := 1
	blockMakerNb := 2
	notarizerNb := 3
	threshold := 3
	var seed int64 = 67912
	blocksize := 100
	blockTime := 500
	finalizeTime := 500

	log.Lvlf1("=> dfinity test with %d nodes: %d beacon, %d bm, %d notarizers", n, beaconNb, blockMakerNb, notarizerNb)
	shares, public := dkg(threshold, notarizerNb)
	notIndex := beaconNb + blockMakerNb
	dfinities := make([]*Dfinity, n, n)
	for i := 0; i < n; i++ {
		c := &Config{
			Seed:         seed,
			Roster:       roster,
			Index:        i,
			N:            n,
			BeaconNb:     beaconNb,
			BlockMakerNb: blockMakerNb,
			NotarizerNb:  notarizerNb,
			Public:       public,
			Threshold:    threshold,
			BlockSize:    blocksize,
			BlockTime:    blockTime,
			FinalizeTime: finalizeTime,
		}
		if i >= notIndex {
			c.Share = shares[i-notIndex]
		}
		dfinities[i] = servers[i].Service(Name).(*Dfinity)
		dfinities[i].SetConfig(c)
	}
	done := make(chan bool)
	cb := func(r int) {
		if r > 10 {
			done <- true
		}
	}
	dfinities[0].AttachCallback(cb)
	go dfinities[0].Start()
	<-done
	fmt.Println(dfinities[n-1].not.finalizer.chain.String())
}

func dkg(t, n int) ([]*share.PriShare, *share.PubPoly) {
	allShares := make([][]*share.PriShare, n)
	var public *share.PubPoly
	for i := 0; i < n; i++ {
		priPoly := share.NewPriPoly(G2, t, nil, random.New())
		allShares[i] = priPoly.Shares(n)
		if public == nil {
			public = priPoly.Commit(G2.Point().Base())
			continue
		}
		public, _ = public.Add(priPoly.Commit(G2.Point().Base()))
	}
	shares := make([]*share.PriShare, n)
	for i := 0; i < n; i++ {
		v := G2.Scalar().Zero()
		for j := 0; j < n; j++ {
			v = v.Add(v, allShares[j][i].V)
		}
		shares[i] = &share.PriShare{I: i, V: v}
	}
	return shares, public

}
