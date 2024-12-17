package keygen

import (
	"fmt"

	"tss-sdk/tss/common"
	"tss-sdk/tss/protocols/utils"
)

func KeygenRound2Exec(sessionId string) (result utils.TssExecResult) {
	round, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}
	round.number = 2
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_2 start", i)

	for j, msg := range round.temp.kgRound1Messages {
		if j == i {
			continue
		}
		r1Msg := msg.Content().(*TKgRound1Message)
		round.temp.V[j] = r1Msg.Hash
		round.temp.KGCs[j] = r1Msg.UnmarshalPolyCommitment()
	}

	// BROADCAST de-commitments
	common.Logger.Infof("party: %d, round_2 broadcast", i)
	{
		r2msg1 := NewKGRound2Message1(
			round.PartyID(),
			round.temp.ssid,
			round.temp.srid,
			round.temp.deCommitPolyG,
			round.temp.commitedA[i],
			round.temp.u,
			round.temp.chainCode,
		)
		round.temp.kgRound2Message1s[i] = r2msg1

		msgWireBytes, router, err := r2msg1.WireBytes()
		if err != nil {
			err := fmt.Sprintf("get r2msg1 wire bytes error: %s", err.Error())
			common.Logger.Error(err)
			result.Err = err
			return
		}
		result.Msg = utils.MpcBroadcastMsg(round.sessionId, round.sessionKind, router, msgWireBytes)
	}

	// P2P send share ij to Pj
	shares := round.temp.shares
	for j, Pj := range round.params.Parties().IDs() {
		r2msg2 := NewKGRound2Message2(Pj, round.PartyID(), shares[j])
		// do not send to this Pj, but store for round 3
		if j == i {
			round.temp.kgRound2Message2s[j] = r2msg2
			continue
		}

		msgWireBytes, router, err := r2msg2.WireBytes()
		if err != nil {
			err := fmt.Sprintf("get r2msg2 wire bytes error: %s", err.Error())
			common.Logger.Error(err)
			result.Err = err
			return
		}
		round.temp.send.kgRound2Message2s[j] = utils.MpcP2pMsg(round.sessionId, round.sessionKind, Pj.Id, router, msgWireBytes)
		if j == i {
			round.temp.kgRound2Message2s[i] = r2msg2
		}
	}

	result.Ok = true
	return result
}

func GetRound2Msg2(sessionId string, toDeviceId string) (result utils.TssExecResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	to, exists := party.DeviceToPartyIndex[toDeviceId]
	if !exists {
		result.Err = fmt.Sprintf("device id %s is not in group %+v", toDeviceId, party.DeviceToPartyIndex)
		return
	}

	result.Ok = true
	result.Msg = party.temp.send.kgRound2Message2s[to]
	return
}

func KeygenRound2Accept(sessionId string, recv []byte) (result utils.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	msg, from, err := utils.ParseMpcMsg(recv, sessionId)
	if err != nil {
		common.Logger.Errorf("parse recv r2msg err: %s", err.Error())
		result.Err = err.Error()
		return
	}

	if _, ok := msg.Content().(*TKgRound2Message1); ok {
		party.temp.kgRound2Message1s[from] = msg
	} else if _, ok := msg.Content().(*TKgRound2Message2); ok {
		party.temp.kgRound2Message2s[from] = msg
	} else {
		result.Err = "not TKgRound2Message"
		return
	}

	result.Ok = true
	return
}

func KeygenRound2Finish(sessionId string) (result utils.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	for j, msg := range party.temp.kgRound2Message2s {
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
