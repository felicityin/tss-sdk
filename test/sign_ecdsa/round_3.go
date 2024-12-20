package sign

import (
	"fmt"

	"github.com/pkg/errors"

	tssdk "tss-sdk/export"
	"tss-sdk/test/tss"
	"tss-sdk/tss/common"
)

func (round *round3) Start() error {
	if round.started {
		return errors.New("round already started")
	}

	round.number = 3
	round.started = true
	round.resetOK()

	msg := tssdk.EcdsaSignRound3Exec(round.sessionId)
	if !msg.Ok {
		common.Logger.Errorf("EcdsaSignRound3Exec err: %s", msg.Err)
		return fmt.Errorf("EcdsaSignRound3Exec err: %s", msg.Err)
	}

	for _, to := range round.devices {
		if to == round.deviceId {
			continue
		}
		r2msg := tssdk.GetSignRound3Msg(round.sessionId, to)
		if !r2msg.Ok {
			common.Logger.Errorf("GetSignRound3Msg err: %s", r2msg.Err)
			return fmt.Errorf("GetSignRound3Msg err: %s", r2msg.Err)
		}
		common.Logger.Infof("[%s] party: %d %s, round_3 p2p to %s", round.sessionId, round.index, round.deviceId, to)
		round.out <- r2msg.Msg
	}
	return nil
}

func (round *round3) Update() (bool, error) {
	res := tssdk.EcdsaSignRound3Finish(round.sessionId)
	if !res.Ok {
		return false, nil // err must be nil, important!!!
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
