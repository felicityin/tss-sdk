package sign

import (
	"fmt"
	"math/big"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/crypto/encproof"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"
)

var ProofParameter = crypto.NewProofConfig(tss.S256().Params().N)

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

	// k, gamma in F_q
	round.temp.k = common.GetRandomPositiveInt(round.params.Rand(), round.params.EC().Params().N)
	round.temp.gamma = common.GetRandomPositiveInt(round.params.Rand(), round.params.EC().Params().N)
	common.Logger.Debugf("P[%d]: calc ki, gammai", i)

	// Ki = enc(k, ρ), Gammai = enc(gamma, mu)
	round.temp.kCiphertexts[i], round.temp.rho, err = round.aux.PaillierPKs[i].EncryptAndReturnRandomness(
		round.params.Rand(),
		round.temp.k,
	)
	if err != nil {
		common.Logger.Errorf("P[%d]: create enc proof failed: %s", i, err)
		result.Err = fmt.Sprintf("P[%d]: create enc proof failed: %s", i, err)
		return
	}
	round.temp.gammaCiphertexts[i], round.temp.mu, err = round.aux.PaillierPKs[i].EncryptAndReturnRandomness(
		round.params.Rand(),
		round.temp.gamma,
	)
	if err != nil {
		common.Logger.Errorf("P[%d]: create enc proof failed: %s", i, err)
		result.Err = fmt.Sprintf("P[%d]: create enc proof failed: %s", i, err)
		return
	}
	common.Logger.Debugf("P[%d]: calc kCiphertext, gammaCiphertext done", i)

	// broadcast Ki, Gammai
	common.Logger.Debugf("P[%d]: broadcast Ki", i)
	r1msg1 := NewSignRound1Message1(round.PartyID(), round.temp.kCiphertexts[i], round.temp.gammaCiphertexts[i])
	round.temp.signRound1Message1s[i] = r1msg1

	// p2p send enc proof to Pj
	for j, Pj := range round.params.Parties().IDs() {
		if j == i {
			round.ok[j] = true
			continue
		}
		contextJ := append(round.temp.ssid, big.NewInt(int64(j)).Bytes()...)

		// M(prove, Πenc, (sid,i), (Iε,Ki); (ki,rhoi))
		encProof, err := encproof.NewEncryptRangeMessage(
			ProofParameter, contextJ, round.temp.kCiphertexts[i],
			round.aux.PaillierPKs[i].N, round.temp.k, round.temp.rho, round.aux.PedersenPKs[j],
		)
		if err != nil {
			common.Logger.Errorf("create enc proof failed: %s, party: %d", err, j)
			result.Err = fmt.Sprintf("create enc proof failed: %s, party: %d", err, j)
			return
		}
		common.Logger.Debugf("P[%d]: calc enc proof", i)

		common.Logger.Debugf("P[%d]: p2p send enc proof", i)
		r1msg2, err := NewSignRound1Message2(Pj, round.PartyID(), encProof)
		if err != nil {
			round.WrapError(err, Pj)
		}
		msgWireBytes, router, err := r1msg2.WireBytes()
		if err != nil {
			common.Logger.Errorf("get r1msg2 wire bytes error: %s", sessionId)
			result.Err = fmt.Sprintf("get r1msg2 wire bytes error: %s", sessionId)
			return
		}
		round.temp.send.signRound1Message2s[j] = utils.MpcP2pMsg(round.sessionId, round.sessionKind, Pj.Id, router, msgWireBytes)
		if j == i {
			round.temp.signRound1Message2s[i] = r1msg2
		}
	}

	msgWireBytes, router, err := r1msg1.WireBytes()
	if err != nil {
		err := fmt.Sprintf("get r1msg1 wire bytes error: %s", sessionId)
		common.Logger.Error(err)
		result.Err = err
		return
	}

	result.Ok = true
	result.Msg = utils.MpcBroadcastMsg(round.sessionId, round.sessionKind, router, msgWireBytes)
	return result
}

func GetRound1Msg2(sessionId string, toDeviceId string) (result utils.TssExecResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	to, exists := party.deviceToPartyIndex[toDeviceId]
	if !exists {
		result.Err = fmt.Sprintf("device id %s is not in group %+v", toDeviceId, party.deviceToPartyIndex)
		return
	}

	result.Ok = true
	result.Msg = party.temp.send.signRound1Message2s[to]
	return
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

	if _, ok := msg.Content().(*SignRound1Message1); ok {
		party.temp.signRound1Message1s[router.From.Index] = msg
	} else if _, ok := msg.Content().(*SignRound1Message2); ok {
		party.temp.signRound1Message2s[router.From.Index] = msg
	} else {
		result.Err = "not SignRound1Message"
		return
	}
	result.Ok = true
	return
}

func OnSignRound1Finish(sessionId string) (result utils.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	for j, msg := range party.temp.signRound1Message2s {
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
