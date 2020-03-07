package simulation

import (
	"reflect"

	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/share"
	"go.dedis.ch/kyber/util/random"
	dfinity "github.com/csanti/dfinity_experiments/service"
	"github.com/dedis/protobuf"
)

func constructors(g kyber.Group) protobuf.Constructors {
	constructors := make(protobuf.Constructors)
	if g != nil {
		var point kyber.Point
		var secret kyber.Scalar
		constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return g.Point() }
		constructors[reflect.TypeOf(&secret).Elem()] = func() interface{} { return g.Scalar() }
	}
	return constructors

}

func dkg(t, n int) ([]*share.PriShare, *share.PubPoly) {
	g2 := dfinity.G2
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
