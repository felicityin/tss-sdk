package keygen

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

	msg := tssdk.TKeygenRound2Exec(round.sessionId)
	if !msg.Ok {
		common.Logger.Errorf("TKeygenRound1Exec err: %s", msg.Err)
		return fmt.Errorf("TKeygenRound1Exec err: %s", msg.Err)
	}

	common.Logger.Infof("[%s] party: %d, %s, round_2 broadcast", round.sessionId, round.index, round.deviceId)
	round.out <- msg.Msg

	for _, to := range round.devices {
		if to == round.deviceId {
			continue
		}
		msg := tssdk.GetTKeygenRound2Msg2(round.sessionId, to)
		if !msg.Ok {
			common.Logger.Errorf("GetTKeygenRound2Msg2 err: %s", msg.Err)
			return fmt.Errorf("GetTKeygenRound2Msg2 err: %s", msg.Err)
		}
		common.Logger.Infof("[%s] party: %d %s, round_2 p2p to %s", round.sessionId, round.index, round.deviceId, to)
		round.out <- msg.Msg
	}
	return nil
}

func (round *round2) Update() (bool, error) {
	res := tssdk.TKeygenRound2Finish(round.sessionId)
	if !res.Ok {
		common.Logger.Errorf("[%s %d] TKeygenRound2Finish err: %s", round.sessionId, round.index, res.Err)
		return false, nil
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
