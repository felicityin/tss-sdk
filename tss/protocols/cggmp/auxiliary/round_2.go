package auxiliary

import (
	"fmt"

	"github.com/golang/protobuf/proto"

	"tss-sdk/tss/common"
	"tss-sdk/tss/protocols/utils"
)

func AuxRound2Exec(sessionId string) (result utils.TssExecResult) {
	round, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	round.number = 2
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_2 start", i)

	for j, msg := range round.temp.auxRound1Messages {
		r1Msg := msg.Content().(*AuxRound1Message)
		round.temp.V[j] = r1Msg.Hash
	}

	prmProofBytes, err := proto.Marshal(round.temp.prmProof)
	if err != nil {
		err = fmt.Errorf("party: %d, marshal prm proof error: %s", i, err.Error())
		common.Logger.Errorf("%s", err.Error())
		result.Err = err.Error()
		return
	}

	common.Logger.Infof("party: %d, round_2 broadcast", i)

	msg := NewAuxRound2Message(
		round.PartyID(),
		round.temp.ssid,
		round.temp.srid,
		round.save.PaillierPKs[i],
		round.save.PedersenPKs[i],
		prmProofBytes,
		round.temp.rho,
		round.temp.u,
	)
	msgWireBytes, router, err := msg.WireBytes()
	if err != nil {
		err = fmt.Errorf("get msg wire bytes error: %s", err.Error())
		common.Logger.Errorf("%s", err.Error())
		result.Err = err.Error()
		return
	}
	round.temp.auxRound2Messages[i] = msg

	result.Ok = true
	result.Msg = utils.MpcBroadcastMsg(round.sessionId, round.sessionKind, router, msgWireBytes)
	return result
}

func AuxRound2Accept(sessionId string, recv []byte) (result utils.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	msg, router, err := utils.ParseMpcMsg(recv, sessionId)
	if err != nil {
		common.Logger.Errorf("parse recv msg err: %s", err.Error())
		result.Err = err.Error()
		return
	}
	party.temp.auxRound2Messages[router.From.Index] = msg

	if _, ok := msg.Content().(*AuxRound2Message); !ok {
		err := fmt.Errorf("not AuxRound2Message")
		common.Logger.Errorf("%s", err.Error())
		result.Err = err.Error()
		return
	}
	result.Ok = true
	return
}

func AuxRound2Finish(sessionId string) (result utils.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	for j, msg := range party.temp.auxRound2Messages {
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
