package auxiliary

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

	msg := tssdk.AuxRound4Exec(round.sessionId)
	if !msg.Ok {
		common.Logger.Errorf("AuxRound4Exec err: %s", msg.Err)
		return fmt.Errorf("AuxRound4Exec err: %s", msg.Err)
	}

	common.Logger.Infof("party: %s, round_4 broadcast", round.deviceId)
	round.end <- &SaveData{
		PartyIndex: round.index,
		Data:       msg.Msg,
	}
	return nil
}

func (round *round4) Update() (bool, error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round4) NextRound() tss.Round {
	return nil // finished!
}
