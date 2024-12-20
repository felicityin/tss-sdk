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

	msg := tssdk.EddsaSignRound1Exec(round.sessionId)
	if !msg.Ok {
		common.Logger.Errorf("EcdsaSignRound1Exec err: %s", msg.Err)
		return fmt.Errorf("EddsaSignRound1Exec err: %s", msg.Err)
	}
	round.out <- msg.Msg
	return nil
}

func (round *round1) Update() (bool, error) {
	res := tssdk.EddsaSignRound1Finish(round.sessionId)
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
