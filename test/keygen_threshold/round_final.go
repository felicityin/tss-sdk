package keygen

import (
	"errors"
	"fmt"

	tssdk "tss-sdk/export"
	"tss-sdk/test/tss"
	"tss-sdk/tss/common"
)

func (round *round4) Start() error {
	if round.started {
		return errors.New("round 4 already started")
	}
	round.number = 4
	round.started = true
	round.resetOK()

	msg := tssdk.TKeygenRound4Exec(round.sessionId)
	if !msg.Ok {
		common.Logger.Errorf("TKeygenRound4Exec err: %s", msg.Err)
		return fmt.Errorf("TKeygenRound4Exec err: %s", msg.Err)
	}

	common.Logger.Infof("party: %s, round_4 broadcast", round.deviceId)
	round.end <- &SaveData{
		PartyIndex: round.index,
		Data:       msg.Msg,
	}
	return nil
}

func (round *round4) Update() (bool, error) {
	return true, nil
}

func (round *round4) NextRound() tss.Round {
	return nil // finished!
}
