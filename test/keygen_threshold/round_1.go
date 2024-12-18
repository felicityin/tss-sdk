package keygen

import (
	"errors"
	"fmt"
	"math/big"

	tssdk "tss-sdk/export"
	"tss-sdk/test/tss"
	"tss-sdk/tss/common"
)

var zero = big.NewInt(0)

// round 1 represents round 1 of the keygen part of the TSS spec
func newRound1(
	n int,
	index int,
	sessionId string,
	sessionKind string,
	deviceId string,
	devices []string,
	out chan<- []byte,
	end chan<- *SaveData,
) tss.Round {
	return &round1{
		&base{n, index, sessionId, sessionKind, deviceId, devices, out, end, make([]bool, n), false, 1},
	}
}

func (round *round1) Start() error {
	if round.started {
		return errors.New("round 1 already started")
	}
	round.number = 1
	round.started = true
	round.resetOK()

	msg := tssdk.TKeygenRound1Exec(round.sessionId)
	if !msg.Ok {
		common.Logger.Errorf("TKeygenRound1Exec err: %s", msg.Err)
		return fmt.Errorf("TKeygenRound1Exec err: %s", msg.Err)
	}

	common.Logger.Infof("party: %d, %s, round_1 broadcast", round.index, round.deviceId)
	round.out <- msg.Msg
	return nil
}

func (round *round1) Update() (bool, error) {
	res := tssdk.TKeygenRound1Finish(round.sessionId)
	if !res.Ok {
		common.Logger.Errorf("TKeygenRound1Finish err: %s, %s", res.Err, round.sessionId)
		return false, nil // err must be nil, import!!!
	}
	for i := 0; i < round.n; i++ {
		round.ok[i] = true
	}
	return true, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
