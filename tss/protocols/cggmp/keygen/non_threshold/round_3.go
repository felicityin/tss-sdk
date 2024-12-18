package keygen

import (
	"bytes"
	"fmt"
	"math/big"
	"strconv"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto/alice/utils"
	"tss-sdk/tss/crypto/schnorr"
	u "tss-sdk/tss/protocols/utils"
)

func KeygenRound3Exec(key string) (result u.TssExecResult) {
	round, ok := Parties[key]
	if !ok {
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	round.number = 3
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_3 start", i)
	var err error

	for j, _ := range round.temp.kgRound2Messages {
		if j == i {
			continue
		}

		r2msg := round.temp.kgRound2Messages[j].Content().(*KGRound2Message)

		round.temp.payload[j], err = r2msg.UnmarshalPayload(round.params.EC())
		if err != nil {
			result.Err = fmt.Sprintf("unmarshal r2msg payload err:%s", err.Error())
			return
		}
		round.data.PubXj[j], err = r2msg.UnmarshalPubXj(round.params.EC())
		if err != nil {
			result.Err = fmt.Sprintf("unmarshal r2msg pubxj err:%s", err.Error())
			return
		}

		if !bytes.Equal(round.temp.payload[j].ssid, round.temp.ssid) {
			common.Logger.Errorf("payload.ssid != round.temp.ssid, party: %d", j)
			result.Err = fmt.Sprintf("payload.ssid != round.temp.ssid, party: %d", j)
			return
		}

		common.Logger.Debugf("party: %d, round_3, calc V", i)
		v := common.SHA512_256(
			round.temp.ssid,
			[]byte(strconv.Itoa(j)),
			round.temp.payload[j].srid,
			round.data.PubXj[j].X().Bytes(),
			round.data.PubXj[j].Y().Bytes(),
			round.temp.payload[j].commitedA.X().Bytes(),
			round.temp.payload[j].commitedA.Y().Bytes(),
			round.temp.payload[j].u,
			r2msg.GetChainCode(),
		)

		// Verify commited V_i
		if !bytes.Equal(v, round.temp.V[j]) {
			common.Logger.Errorf("hash != V, party: %d", j)
			result.Err = fmt.Sprintf("hash != V, party: %d", j)
			return
		}

		// Set srid as xor of all party's srid_i
		common.Logger.Debugf("party: %d, round_3, calc srid", i)
		round.temp.srid = utils.Xor(round.temp.srid, round.temp.payload[j].srid)

		round.temp.chainCode = utils.Xor(round.temp.chainCode, r2msg.GetChainCode())
	}

	common.Logger.Debugf("party: %d, round_3, calc challenge", i)
	challenge := common.RejectionSample(
		round.params.EC().Params().N,
		common.SHA512_256i_TAGGED(
			append(round.temp.ssid, round.temp.srid...),
			big.NewInt(int64(i)),
			round.data.PubXj[i].X(),
			round.data.PubXj[i].Y(),
			round.temp.commitedA.X(),
			round.temp.commitedA.Y(),
		),
	)

	round.data.ChainCode = new(big.Int).SetBytes(round.temp.chainCode)

	// Generate schnorr proof
	common.Logger.Debugf("party: %d, round_3, calc schnorr proof", i)
	schProof := schnorr.Prove(round.params.EC().Params().N, round.temp.tau, challenge, round.data.PrivXi)

	// BROADCAST proofs
	common.Logger.Infof("party: %d, round_3 broadcast", i)
	msg := NewKGRound3Message(round.PartyID(), schProof.Proof.Bytes())
	msgWireBytes, router, err := msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", key)
		result.Err = fmt.Sprintf("get msg wire bytes error: %s", key)
		return
	}
	round.temp.kgRound3Messages[i] = msg

	result.Ok = true
	result.Msg = u.MpcBroadcastMsg(round.sessionId, round.sessionKind, router, msgWireBytes)
	return result
}

func KeygenRound3Accept(sessionId string, recv []byte) (result u.TssResult) {
	party, ok := Parties[sessionId]
	if !ok {
		common.Logger.Errorf("party not found: %s", sessionId)
		result.Err = fmt.Sprintf("party not found: %s", sessionId)
		return
	}

	msg, router, err := u.ParseMpcMsg(recv, sessionId)
	if err != nil {
		common.Logger.Errorf("parse recv msg err: %s", err.Error())
		result.Err = err.Error()
		return
	}

	if _, ok := msg.Content().(*KGRound3Message); !ok {
		result.Err = fmt.Sprintf("not KGRound3Message, err:%s", err.Error())
		return
	}

	result.Ok = true
	party.temp.kgRound3Messages[router.From.Index] = msg
	return
}

func KeygenRound3Finish(key string) (result u.TssResult) {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	for j, msg := range party.temp.kgRound3Messages {
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
