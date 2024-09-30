package sign

import (
	"encoding/base64"
	"fmt"
	"math/big"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/tss"
)

func OnSignRound1Exec(key string) (result OnsignExecResult) {
	round, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	round.number = 1
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	common.Logger.Infof("[sign] party: %d, round_1 start", i)

	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	var err error
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
	msgWireBytes, _, err := msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", key)
		result.Err = fmt.Sprintf("get msg wire bytes error: %s", key)
		return
	}
	round.temp.signRound1Messages[i] = msgWireBytes

	result.Ok = true
	result.MsgWireBytes = msgWireBytes
	return result
}

func OnSignRound1MsgAccept(key string, from int, msgWireBytes string) (result OnsignResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	rMsgBytes, err := base64.StdEncoding.DecodeString(msgWireBytes)
	if err != nil {
		common.Logger.Errorf("msg error, msg base64 decode fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, msg base64 decode fail, err:%s", err.Error())
		return
	}

	msg, err := tss.ParseWireMsg(rMsgBytes)
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
		return
	}

	if _, ok := msg.Content().(*SignRound1Message); ok {
		party.temp.signRound1Messages[from] = rMsgBytes
	} else {
		result.Err = "not SignRound1Message"
		return
	}
	result.Ok = true
	return
}

func OnSignRound1Finish(key string) (result OnsignResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	for j, msg := range party.temp.signRound1Messages {
		if len(msg) == 0 {
			result.Err = fmt.Sprintf("msg is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
