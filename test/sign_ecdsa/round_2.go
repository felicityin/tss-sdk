package sign

import (
	"errors"
	"fmt"

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

	msg := tssdk.EcdsaSignRound2Exec(round.sessionId)
	if !msg.Ok {
		common.Logger.Errorf("EcdsaSignRound2Exec err: %s", msg.Err)
		return fmt.Errorf("EcdsaSignRound2Exec err: %s", msg.Err)
	}

	for _, to := range round.devices {
		if to == round.deviceId {
			continue
		}
		r2msg := tssdk.GetSignRound2Msg(round.sessionId, to)
		if !r2msg.Ok {
			common.Logger.Errorf("GetSignRound2Msg err: %s", r2msg.Err)
			return fmt.Errorf("GetSignRound2Msg err: %s", r2msg.Err)
		}
		common.Logger.Infof("[%s] party: %d %s, round_2 p2p to %s", round.sessionId, round.index, round.deviceId, to)
		round.out <- r2msg.Msg
	}
	return nil
}

func (round *round2) Update() (bool, error) {
	res := tssdk.EcdsaSignRound2Finish(round.sessionId)
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
	return &round3{round}
}
