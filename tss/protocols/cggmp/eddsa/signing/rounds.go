package signing

import (
	"tss-sdk/tss/common"
	"tss-sdk/tss/protocols/cggmp/eddsa/presign"
	"tss-sdk/tss/protocols/cggmp/keygen"
	"tss-sdk/tss/tss"
)

const (
	TaskName = "eddsa-sign"
)

type (
	base struct {
		*tss.Parameters
		isThreshold bool
		key         *keygen.LocalPartySaveData
		pre         *presign.LocalPartySaveData
		data        *common.SignatureData
		temp        *localTempData
		out         chan<- tss.Message
		end         chan<- *common.SignatureData
		ok          []bool // `ok` tracks parties which have been verified by Update()
		started     bool
		number      int
	}
	round1 struct {
		*base
	}
	finalization struct {
		*round1
	}
)

var (
	_ tss.Round = (*round1)(nil)
	_ tss.Round = (*finalization)(nil)
)

// ----- //

func (round *base) Params() *tss.Parameters {
	return round.Parameters
}

func (round *base) RoundNumber() int {
	return round.number
}

// CanProceed is inherited by other rounds
func (round *base) CanProceed() bool {
	if !round.started {
		return false
	}
	for _, ok := range round.ok {
		if !ok {
			return false
		}
	}
	return true
}

// WaitingFor is called by a Party for reporting back to the caller
func (round *base) WaitingFor() []*tss.PartyID {
	Ps := round.Parties().IDs()
	ids := make([]*tss.PartyID, 0, len(round.ok))
	for j, ok := range round.ok {
		if ok {
			continue
		}
		ids = append(ids, Ps[j])
	}
	return ids
}

func (round *base) WrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskName, round.number, round.PartyID(), culprits...)
}

// ----- //

// `ok` tracks parties which have been verified by Update()
func (round *base) resetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}

// get ssid from local params
func (round *base) getSSID() ([]byte, error) {
	return []byte("eddsa-signing"), nil
}
