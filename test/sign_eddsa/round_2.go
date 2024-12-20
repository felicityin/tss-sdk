package sign

import (
	"fmt"

	"github.com/pkg/errors"

	tssdk "tss-sdk/export"
	"tss-sdk/test/tss"
	"tss-sdk/tss/common"
)

func (round *round2) Start() error {
	if round.started {
		return errors.New("round already started")
	}

	round.number = 2
	round.started = true
	round.resetOK()

	msg := tssdk.EddsaSignRound2Exec(round.sessionId)
	if !msg.Ok {
		common.Logger.Errorf("E2dsaSignRound2Exec err: %s", msg.Err)
		return fmt.Errorf("EddsaSignRound2Exec err: %s", msg.Err)
	}
	round.out <- msg.Msg

	return nil
}

func (round *round2) Update() (bool, error) {
	res := tssdk.EddsaSignRound2Finish(round.sessionId)
	if !res.Ok {
		return false, nil // err must be nil, important!!!
	}
	for i := 0; i < round.n; i++ {
		round.ok[i] = true
	}
	return true, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
