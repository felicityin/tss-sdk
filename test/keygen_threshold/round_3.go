package keygen

import (
	"errors"
	"fmt"

	tssdk "tss-sdk/export"
	"tss-sdk/test/tss"
	"tss-sdk/tss/common"
)

func (round *round3) Start() error {
	if round.started {
		return errors.New("round 3 already started")
	}
	round.number = 3
	round.started = true
	round.resetOK()

	msg := tssdk.TKeygenRound3Exec(round.sessionId)
	if !msg.Ok {
		common.Logger.Errorf("TKeygenRound3Exec err: %s", msg.Err)
		return fmt.Errorf("TKeygenRound3Exec err: %s", msg.Err)
	}

	common.Logger.Infof("party: %s, round_3 broadcast", round.deviceId)
	round.out <- msg.Msg
	return nil
}

func (round *round3) Update() (bool, error) {
	res := tssdk.TKeygenRound3Finish(round.sessionId)
	if !res.Ok {
		return false, nil
	}
	for i := 0; i < round.n; i++ {
		round.ok[i] = true
	}
	return true, nil
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
