package auxiliary

import (
	"errors"
	"fmt"

	tssdk "tss-sdk/export"
	"tss-sdk/test/tss"
	"tss-sdk/tss/common"
)

func (round *round2) Start() error {
	if round.started {
		return errors.New("round 2 already started")
	}
	round.number = 2
	round.started = true
	round.resetOK()

	msg := tssdk.AuxRound2Exec(round.sessionId)
	if !msg.Ok {
		common.Logger.Errorf("AuxRound2Exec err: %s", msg.Err)
		return fmt.Errorf("AuxRound2Exec err: %s", msg.Err)
	}
	common.Logger.Infof("[%s] party: %d, %s, round_2 broadcast", round.sessionId, round.index, round.deviceId)
	round.out <- msg.Msg
	return nil
}

func (round *round2) Update() (bool, error) {
	res := tssdk.AuxRound2Finish(round.sessionId)
	if !res.Ok {
		common.Logger.Errorf("AuxRound2Finish err: %s, %s", res.Err, round.sessionId)
		return false, nil // err must be nil, import!!!
	}
	for i := 0; i < round.n; i++ {
		round.ok[i] = true
	}
	return true, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
