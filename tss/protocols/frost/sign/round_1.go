package sign

import (
	"fmt"
	"math/big"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/protocols/utils"
)

func OnSignRound1Exec(sessionId string) (result utils.TssExecResult) {
	round, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	round.number = 1
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	common.Logger.Infof("[sign] party: %d, round_1 start", i)

	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	round.temp.ssid, err = round.getSSID()
	if err != nil {
		return
	}

	round.temp.d = common.GetRandomPositiveInt(round.params.Rand(), round.params.EC().Params().N)
	round.temp.e = common.GetRandomPositiveInt(round.params.Rand(), round.params.EC().Params().N)

	D := crypto.ScalarBaseMult(round.params.EC(), round.temp.d)
	E := crypto.ScalarBaseMult(round.params.EC(), round.temp.e)

	common.Logger.Debugf("P[%d]: round_1 broadcast", i)
	msg, err := NewSignRound1Message(round.PartyID(), D, E)
	if err != nil {
		common.Logger.Errorf("P[%d]: NewSignRound1Message err: %s", i, err.Error())
		result.Err = fmt.Sprintf("P[%d]: NewSignRound1Message err: %s", i, err.Error())
	}
	msgWireBytes, router, err := msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", sessionId)
		result.Err = fmt.Sprintf("get msg wire bytes error: %s", sessionId)
		return
	}
	round.temp.signRound1Messages[i] = msg

	result.Ok = true
	result.Msg = utils.MpcBroadcastMsg(round.sessionId, round.sessionKind, router, msgWireBytes)
	return result
}

func OnSignRound1MsgAccept(sessionId string, recv []byte) (result utils.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	msg, router, err := utils.ParseMpcMsg(recv, sessionId)
	if err != nil {
		common.Logger.Errorf("parse recv r1msg err: %s", err.Error())
		result.Err = err.Error()
		return
	}

	if _, ok := msg.Content().(*SignRound1Message); !ok {
		result.Err = "not SignRound1Message"
		return
	}

	party.temp.signRound1Messages[router.From.Index] = msg
	result.Ok = true
	return
}

func OnSignRound1Finish(sessionId string) (result utils.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	for j, msg := range party.temp.signRound1Messages {
		if msg == nil {
			result.Err = fmt.Sprintf("r1msg is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
