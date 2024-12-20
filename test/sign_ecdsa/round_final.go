package sign

import (
	"errors"
	"fmt"

	tssdk "tss-sdk/export"
	"tss-sdk/test/tss"
	"tss-sdk/tss/common"
)

func (round *finalization) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 5
	round.started = true
	round.resetOK()

	msg := tssdk.EcdsaSignRound5Exec(round.sessionId)
	if !msg.Ok {
		common.Logger.Errorf("EcdsaSignRound5Exec err: %s", msg.Err)
		return fmt.Errorf("EcdsaSignRound5Exec err: %s", msg.Err)
	}
	round.end <- &SaveData{
		PartyIndex: round.index,
		Data:       msg.Msg,
	}
	return nil
}

func (round *finalization) Update() (bool, error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
