package auxiliary

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

	msg := tssdk.AuxRound3Exec(round.sessionId)
	if !msg.Ok {
		common.Logger.Errorf("AuxRound3Exec err: %s", msg.Err)
		return fmt.Errorf("AuxRound3Exec err: %s", msg.Err)
	}

	for _, to := range round.devices {
		if to == round.deviceId {
			continue
		}
		msg := tssdk.GetAuxRound3Msg(round.sessionId, to)
		if !msg.Ok {
			common.Logger.Errorf("GetAuxRound3Msg2 err: %s", msg.Err)
			return fmt.Errorf("GetAuxRound3Msg err: %s", msg.Err)
		}
		common.Logger.Infof("[%s] party: %d %s, round_3 p2p to %s", round.sessionId, round.index, round.deviceId, to)
		round.out <- msg.Msg
	}
	return nil
}

func (round *round3) Update() (bool, error) {
	res := tssdk.AuxRound3Finish(round.sessionId)
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
