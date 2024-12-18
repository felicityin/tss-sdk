package keygen

import (
	"fmt"
	"math/big"
	"strconv"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	cmts "tss-sdk/tss/crypto/commitments"
	"tss-sdk/tss/crypto/vss"
	"tss-sdk/tss/protocols/utils"
)

var zero = big.NewInt(0)

func KeygenRound1Exec(sessionId string) (result utils.TssExecResult) {
	round, err := GetParty(sessionId)
	if err != nil {
		common.Logger.Errorf("KeygenRound1Exec GetParty err: %s, sessionId: %s", err.Error(), sessionId)
		result.Err = err.Error()
		return
	}
	round.number = 1
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	common.Logger.Infof("[%s] party: %d, round_1 start", sessionId, i)

	if round.data.PrivXi == nil {
		round.data.PrivXi = common.GetRandomPositiveInt(round.params.PartialKeyRand(), round.params.EC().Params().N)
	}
	if round.data.ChainCode == nil {
		round.temp.chainCode, _ = common.GetRandomBytes(round.params.Rand(), 32)
	} else {
		round.temp.chainCode = round.data.ChainCode.Bytes()
	}

	// "partial" key share s0
	round.temp.s0 = round.data.PrivXi

	// Compute the vss shares
	ids := round.params.Parties().IDs().Keys()
	vs, shares, err := vss.Create(round.params.EC(), round.params.Threshold(), round.temp.s0, ids)
	if err != nil {
		result.Err = fmt.Sprintf("vss.Create err: %s", err.Error())
		return
	}
	round.data.Ks = ids
	round.temp.vs = vs
	round.temp.shares = shares

	// Make commitment -> (C, D)
	pGFlat, err := crypto.FlattenECPoints(vs)
	if err != nil {
		err := fmt.Sprintf("crypto.FlattenECPoints err: %s", err.Error())
		common.Logger.Error(err)
		result.Err = err
		return
	}
	polyCmt := cmts.NewHashCommitment(round.params.Rand(), pGFlat...)
	round.temp.deCommitPolyG = polyCmt.D
	round.temp.KGCs[i] = polyCmt.C

	// Make zk-schnorr commitment
	round.temp.tau = common.GetRandomPositiveInt(round.params.PartialKeyRand(), round.params.EC().Params().N)
	round.temp.commitedA[i] = crypto.ScalarBaseMult(round.params.EC(), round.temp.tau)

	round.data.ShareID = ids[i]
	round.temp.srid, _ = common.GetRandomBytes(round.params.Rand(), 32)
	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	ssid, err := round.getSSID()
	if err != nil {
		err := fmt.Sprintf("get ssid err: %s", err.Error())
		common.Logger.Error(err)
		result.Err = err
		return
	}
	round.temp.ssid = ssid

	round.temp.u, _ = common.GetRandomBytes(round.params.Rand(), 32)

	// Compute V_i
	Vi := common.SHA512_256(
		ssid,
		[]byte(strconv.Itoa(round.params.PartyCount())),
		[]byte(strconv.Itoa(i)),
		[]byte(strconv.Itoa(round.params.Threshold())),
		round.temp.srid,
		polyCmt.C.Bytes(),
		round.temp.commitedA[i].X().Bytes(),
		round.temp.commitedA[i].Y().Bytes(),
		round.temp.u,
		round.temp.chainCode,
	)

	common.Logger.Infof("[%s] party: %d, round_1 broadcast", sessionId, i)

	msg := NewKGRound1Message(round.PartyID(), Vi, polyCmt.C)
	msgWireBytes, router, err := msg.WireBytes()
	if err != nil {
		err := fmt.Sprintf("get msg wire bytes error: %s", err.Error())
		common.Logger.Error(err)
		result.Err = err
		return
	}
	round.temp.kgRound1Messages[i] = msg

	result.Ok = true
	result.Msg = utils.MpcBroadcastMsg(round.sessionId, round.sessionKind, router, msgWireBytes)
	return
}

func KeygenRound1Accept(sessionId string, recv []byte) (result utils.TssResult) {
	party, ok := Parties[sessionId]
	if !ok {
		err := fmt.Sprintf("party not found: %s", sessionId)
		common.Logger.Error(err)
		result.Err = err
		return
	}

	msg, router, err := utils.ParseMpcMsg(recv, sessionId)
	if err != nil {
		common.Logger.Errorf("parse recv r1msg err: %s", err.Error())
		result.Err = err.Error()
		return
	}

	if _, ok := msg.Content().(*TKgRound1Message); !ok {
		result.Err = fmt.Sprintf("not TKgRound1Message, err: %s", err.Error())
		return
	}

	result.Ok = true
	party.temp.kgRound1Messages[router.From.Index] = msg
	common.Logger.Infof("[%s %s] KeygenRound1Accept recv msg from  %d", router.Round, sessionId, router.From.Index)
	return
}

func KeygenRound1Finish(sessionId string) (result utils.TssResult) {
	party, ok := Parties[sessionId]
	if !ok {
		err := fmt.Sprintf("party not found: %s", sessionId)
		common.Logger.Error(err)
		result.Err = err
		return
	}

	for j, msg := range party.temp.kgRound1Messages {
		if j == party.PartyID().Index {
			continue
		}
		if msg == nil {
			err := fmt.Sprintf("[%s] msg is null: %d", sessionId, j)
			common.Logger.Error(err)
			result.Err = err
			return
		}
	}
	result.Ok = true
	return
}
