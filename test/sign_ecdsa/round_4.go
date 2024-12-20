package sign

import (
	"errors"
	"fmt"

	tssdk "tss-sdk/export"
	"tss-sdk/test/tss"
	"tss-sdk/tss/common"
)

func (round *round4) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 4
	round.started = true
	round.resetOK()

	msg := tssdk.EcdsaSignRound4Exec(round.sessionId)
	if !msg.Ok {
		common.Logger.Errorf("EcdsaSignRound4Exec err: %s", msg.Err)
		return fmt.Errorf("EcdsaSignRound4Exec err: %s", msg.Err)
	}
	round.out <- msg.Msg
	return nil
}

func (round *round4) Update() (bool, error) {
	res := tssdk.EcdsaSignRound4Finish(round.sessionId)
	if !res.Ok {
		return false, nil // err must be nil, important!!!
	}
	for i := 0; i < round.n; i++ {
		round.ok[i] = true
	}
	return true, nil
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
