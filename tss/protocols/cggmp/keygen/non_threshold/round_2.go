package keygen

import (
	"encoding/base64"
	"fmt"

	"tss-sdk/tss/common"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"
)

func KeygenRound2Exec(key string) (result utils.TssExecResult) {
	round, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
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

	var err error
	msgWireBytes, _, err := msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", key)
		result.Err = fmt.Sprintf("get msg wire bytes error: %s", key)
		return
	}

	result.Ok = true
	result.MsgWireBytes = msgWireBytes
	return result
}

func KeygenRound2Accept(key string, from int, msgWireBytes string) (result utils.TssResult) {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	rMsgBytes, err := base64.StdEncoding.DecodeString(msgWireBytes)
	if err != nil {
		common.Logger.Errorf("msg error, msg base64 decode fail, err: %s", err.Error())
		result.Err = fmt.Sprintf("msg error, msg base64 decode fail, err: %s", err.Error())
		return
	}

	msg, err := tss.ParseWireMsg(rMsgBytes)
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err: %s", err.Error())
		result.Err = fmt.Sprintf("msg error, parse wire msg fail, err: %s", err.Error())
		return
	}
	if _, ok := msg.Content().(*KGRound2Message); !ok {
		result.Err = fmt.Sprintf("not KGRound2Message, err:%s", err.Error())
		return
	}
	result.Ok = true
	party.temp.kgRound2Messages[from] = msg
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
