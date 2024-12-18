package keygen

import (
	"fmt"

	"tss-sdk/tss/common"
	"tss-sdk/tss/protocols/utils"
)

func KeygenRound2Exec(sessionId string) (result utils.TssExecResult) {
	round, ok := Parties[sessionId]
	if !ok {
		common.Logger.Errorf("party not found: %s", sessionId)
		result.Err = fmt.Sprintf("party not found: %s", sessionId)
		return
	}

	round.number = 2
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_2 start", i)

	for j := 0; j < len(round.temp.kgRound1Messages); j++ {
		r1Msg := round.temp.kgRound1Messages[j].Content().(*KGRound1Message)
		round.temp.V[j] = r1Msg.Commitment
	}

	common.Logger.Infof("party: %d, round_2 broadcast", i)
	msg := NewKGRound2Message(
		round.PartyID(),
		round.temp.ssid,
		round.temp.srid,
		round.data.PubXj[i],
		round.temp.commitedA,
		round.temp.u,
		round.temp.chainCode,
	)
	round.temp.kgRound2Messages[i] = msg

	msgWireBytes, router, err := msg.WireBytes()
	if err != nil {
		err := fmt.Sprintf("get msg wire bytes error: %s", err.Error())
		common.Logger.Error(err)
		result.Err = err
		return
	}

	result.Ok = true
	result.Msg = utils.MpcBroadcastMsg(round.sessionId, round.sessionKind, router, msgWireBytes)
	return result
}

func KeygenRound2Accept(sessionId string, recv []byte) (result utils.TssResult) {
	party, ok := Parties[sessionId]
	if !ok {
		common.Logger.Errorf("party not found: %s", sessionId)
		result.Err = fmt.Sprintf("party not found: %s", sessionId)
		return
	}

	msg, router, err := utils.ParseMpcMsg(recv, sessionId)
	if err != nil {
		common.Logger.Errorf("parse recv msg err: %s", err.Error())
		result.Err = err.Error()
		return
	}

	if _, ok := msg.Content().(*KGRound2Message); !ok {
		result.Err = fmt.Sprintf("not KGRound2Message, err:%s", err.Error())
		return
	}
	result.Ok = true
	party.temp.kgRound2Messages[router.From.Index] = msg
	return
}

func KeygenRound2Finish(key string) (result utils.TssResult) {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	for j, msg := range party.temp.kgRound2Messages {
		if j == party.PartyID().Index {
			continue
		}
		if msg == nil {
			result.Err = fmt.Sprintf("msg is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
