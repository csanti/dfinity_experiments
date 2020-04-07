package simulation

import (
	"time"

	"github.com/BurntSushi/toml"
	dfinity "github.com/csanti/dfinity_experiments/service"
	"github.com/csanti/onet"
	"github.com/csanti/onet/log"
	"github.com/csanti/onet/simul/monitor"
)

// Name is the name of the simulation
var Name = "dfinity"

func init() {
	onet.SimulationRegister(Name, NewSimulation)
}

// config being passed down to all nodes, each one takes the relevant
// information
type config struct {
	Seed         int64
	BeaconNb     int
	BlockMakerNb int
	NotarizerNb  int
	Threshold    int
	BlockSize    int
	BlockTime    int
	FinalizeTime int
}

// Simulation runs a simulated version of the dfinity blockchain
type Simulation struct {
	onet.SimulationBFTree
	config
}

// NewSimulation returns a dfinity simulation out of the given config
func NewSimulation(config string) (onet.Simulation, error) {
	s := &Simulation{}
	_, err := toml.Decode(config, s)
	return s, err
}

func (s *Simulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sim := new(onet.SimulationConfig)
	s.CreateRoster(sim, hosts, 2000)
	s.CreateTree(sim)
	// create the shares manually
	return sim, nil
}

func (s *Simulation) DistributeConfig(config *onet.SimulationConfig) {
	shares, public := dkg(s.Threshold, s.NotarizerNb)
	n := len(config.Roster.List)
	notIndex := s.BeaconNb + s.BlockMakerNb
	_, commits := public.Info()
	for i, si := range config.Roster.List {
		c := &dfinity.Config{
			Seed:         s.Seed,
			Roster:       config.Roster,
			Index:        i,
			N:            n,
			BeaconNb:     s.BeaconNb,
			BlockMakerNb: s.BlockMakerNb,
			NotarizerNb:  s.NotarizerNb,
			Threshold:    s.Threshold,
			BlockSize:    s.BlockSize,
			BlockTime:    s.BlockTime,
			FinalizeTime: s.FinalizeTime,
			Public:       commits,
		}
		if i >= notIndex {
			c.Share = shares[i-notIndex]
		}
		if i == 0 {
			config.GetService(dfinity.Name).(*dfinity.Dfinity).SetConfig(c)
		} else {
			config.Server.Send(si, c)
		}
	}
}

func (s *Simulation) Run(config *onet.SimulationConfig) error {
	log.Lvl1("distributing config to all nodes...")
	s.DistributeConfig(config)
	log.Lvl1("Sleeping for the config to dispatch correctly")
	time.Sleep(1 * time.Second)
	log.Lvl1("Starting dfinity simulation")
	dfinity := config.GetService(dfinity.Name).(*dfinity.Dfinity)

	var roundDone int
	done := make(chan bool)
	newRoundCb := func(round int) {
		roundDone++
		log.Lvl1("Simulation Round #", round, "incorporated")
		if roundDone > s.Rounds {
			done <- true
		}
	}

	dfinity.AttachCallback(newRoundCb)
	fullTime := monitor.NewTimeMeasure("finalizing")
	dfinity.Start()
	select {
	case <-done:
		break
		//case <-time.After(30 * time.Second):
		//panic("not finished yet")

	}
	fullTime.Record()
	monitor.RecordSingleMeasure("blocks", float64(roundDone))
	log.Lvl1(" ---------------------------")
	log.Lvl1("End of simulation => ", roundDone, " rounds done")
	log.Lvl1(" ---------------------------")
	return nil
}
