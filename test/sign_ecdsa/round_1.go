package sign

import (
	"errors"
	"fmt"

	tssdk "tss-sdk/export"
	"tss-sdk/test/tss"
	"tss-sdk/tss/common"
)

// round 1 represents round 1 of the signing part of the EDDSA TSS spec
func newRound1(
	n int,
	index int,
	sessionId string,
	deviceId string,
	devices []string,
	out chan<- []byte,
	end chan<- *SaveData,
) tss.Round {
	return &round1{
		&base{n, index, sessionId, deviceId, devices, out, end, make([]bool, n), false, 1},
	}
}

func (round *round1) Start() error {
	if round.started {
		return errors.New("round already started")
	}

	round.number = 1
	round.started = true
	round.resetOK()

	r1msg1 := tssdk.EcdsaSignRound1Exec(round.sessionId)
	if !r1msg1.Ok {
		common.Logger.Errorf("EcdsaSignRound1Exec err: %s", r1msg1.Err)
		return fmt.Errorf("EcdsaSignRound1Exec err: %s", r1msg1.Err)
	}
	round.out <- r1msg1.Msg

	for _, to := range round.devices {
		if to == round.deviceId {
			continue
		}
		r1msg2 := tssdk.GetSignRound1Msg2(round.sessionId, to)
		if !r1msg2.Ok {
			common.Logger.Errorf("GetSignRound1Msg2 err: %s", r1msg2.Err)
			return fmt.Errorf("GetSignRound1Msg2 err: %s", r1msg2.Err)
		}
		common.Logger.Infof("[%s] party: %d %s, round_1 p2p to %s", round.sessionId, round.index, round.deviceId, to)
		round.out <- r1msg2.Msg
	}
	return nil
}

func (round *round1) Update() (bool, error) {
	res := tssdk.EcdsaSignRound1Finish(round.sessionId)
	if !res.Ok {
		return false, nil // err must be nil, important!!!
	}
	for i := 0; i < round.n; i++ {
		round.ok[i] = true
	}
	return true, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
