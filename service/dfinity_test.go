package service

import (
	"fmt"
	"testing"
	"time"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing"
	"github.com/dedis/kyber/share"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
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
	dfinities := make([]*dfinity, n, n)
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
		dfinities[i] = servers[i].Service(dfinityName).(*dfinity)
		dfinities[i].SetConfig(c)
	}
	time.Sleep(3 * time.Second)
	fmt.Println(dfinities[n-1].not.finalizer.chain.String())
}

func dkg(t, n int) ([]*share.PriShare, *share.PubPoly) {
	allShares := make([][]*share.PriShare, n)
	var public *share.PubPoly
	for i := 0; i < n; i++ {
		priPoly := share.NewPriPoly(g2, t, nil, random.New())
		allShares[i] = priPoly.Shares(n)
		if public == nil {
			public = priPoly.Commit(g2.Point().Base())
			continue
		}
		public, _ = public.Add(priPoly.Commit(g2.Point().Base()))
	}
	shares := make([]*share.PriShare, n)
	for i := 0; i < n; i++ {
		v := g2.Scalar().Zero()
		for j := 0; j < n; j++ {
			v = v.Add(v, allShares[j][i].V)
		}
		shares[i] = &share.PriShare{I: i, V: v}
	}
	return shares, public

}
