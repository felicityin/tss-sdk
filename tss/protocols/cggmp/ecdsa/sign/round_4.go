package sign

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/protocols/utils"
)

func OnsignRound4Exec(sessionId string) (result utils.TssExecResult) {
	round, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	round.number = 4
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	common.Logger.Infof("[sign] party: %d, round4 start", i)

	sumDelta := new(big.Int).Set(round.temp.delta)
	sumBigDelta := round.temp.Delta

	for j := range round.params.Parties().IDs() {
		if j == i {
			continue
		}
		contextJ := append(round.temp.ssid, big.NewInt(int64(j)).Bytes()...)

		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)

		Delta, err := r3msg.UnmarshalBigDelta()
		if err != nil {
			result.Err = fmt.Sprintf("[j: %d] unmarshal big delta err: %s", j, err.Error())
			return
		}

		logProof, err := r3msg.UnmarshalLogProof()
		if err != nil {
			result.Err = fmt.Sprintf("[j: %d] unmarshal log proof err: %s", j, err.Error())
			return
		}
		if err = logProof.Verify(
			ProofParameter, contextJ, round.temp.kCiphertexts[j], round.aux.PaillierPKs[j].N,
			round.aux.PedersenPKs[i], Delta, round.temp.sumGamma,
		); err != nil {
			common.Logger.Errorf("[j: %d] verify log proof failed: %s, party: %d", j, err)
			result.Err = fmt.Sprintf("[j: %d] verify log proof failed: %s, party: %d", j, err)
			return
		}

		sumDelta.Add(sumDelta, r3msg.UnmarshalDelta())

		sumBigDelta, err = sumBigDelta.Add(Delta)
		if err != nil {
			result.Err = fmt.Sprintf("sumBigDelta.Add err: %s", err)
			return
		}
	}

	gDelta := crypto.ScalarBaseMult(round.params.EC(), sumDelta)

	if hex.EncodeToString(gDelta.X().Bytes()) != hex.EncodeToString(sumBigDelta.X().Bytes()) ||
		hex.EncodeToString(gDelta.Y().Bytes()) != hex.EncodeToString(sumBigDelta.Y().Bytes()) {
		result.Err = "verify delta failed"
		return
	}

	round.temp.R = round.temp.sumGamma.ScalarMult(new(big.Int).ModInverse(sumDelta, round.params.EC().Params().N))

	modN := common.ModInt(round.params.EC().Params().N)
	round.temp.si = modN.Add(modN.Mul(round.temp.k, round.temp.msg), modN.Mul(round.temp.R.X(), round.temp.chi))

	// broadcast sigma
	common.Logger.Debugf("P[%d]: broadcast sigma", i)
	r4msg := NewSignRound4Message(round.PartyID(), round.temp.si)
	msgWireBytes, router, err := r4msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get r4msg wire bytes error: %s", sessionId)
		result.Err = fmt.Sprintf("get r4msg wire bytes error: %s", sessionId)
		return
	}
	round.temp.signRound4Messages[i] = r4msg

	result.Ok = true
	result.Msg = utils.MpcBroadcastMsg(round.sessionId, round.sessionKind, router, msgWireBytes)
	return result
}

func OnSignRound4MsgAccept(sessionId string, recv []byte) (result utils.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	msg, router, err := utils.ParseMpcMsg(recv, sessionId)
	if err != nil {
		common.Logger.Errorf("parse recv r4msg err: %s", err.Error())
		result.Err = err.Error()
		return
	}

	if _, ok := msg.Content().(*SignRound4Message); !ok {
		result.Err = "not SignRound4Message"
		return
	}

	result.Ok = true
	party.temp.signRound4Messages[router.From.Index] = msg
	return
}

func OnSignRound4Finish(sessionId string) (result utils.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	for j, msg := range party.temp.signRound4Messages {
		if j == party.PartyID().Index {
			continue
		}
		if msg == nil {
			result.Err = fmt.Sprintf("r4msg is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
