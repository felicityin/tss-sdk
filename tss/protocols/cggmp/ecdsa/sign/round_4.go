package sign

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"
)

func OnsignRound4Exec(key string) (result utils.TssExecResult) {
	round, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
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
	msgWireBytes, _, err := r4msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get r4msg wire bytes error: %s", key)
		result.Err = fmt.Sprintf("get r4msg wire bytes error: %s", key)
		return
	}
	round.temp.signRound4Messages[i] = r4msg

	result.Ok = true
	result.MsgWireBytes = msgWireBytes
	return result
}

func OnSignRound4MsgAccept(key string, from int, msgWireBytes string) (result utils.TssResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	rMsgBytes, err := base64.StdEncoding.DecodeString(msgWireBytes)
	if err != nil {
		common.Logger.Errorf("msg error, r3msg base64 decode fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, r3msg base64 decode fail, err:%s", err.Error())
		return
	}

	msg, err := tss.ParseWireMsg(rMsgBytes)
	if err != nil {
		common.Logger.Errorf("msg error, parse wire r4msg fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, parse wire r4msg fail, err:%s", err.Error())
		return
	}
	if _, ok := msg.Content().(*SignRound4Message); !ok {
		result.Err = "not SignRound3Message"
		return
	}

	result.Ok = true
	party.temp.signRound4Messages[from] = msg
	return
}

func OnSignRound4Finish(key string) (result utils.TssResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
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
