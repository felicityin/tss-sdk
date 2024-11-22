package sign

import (
	"encoding/base64"
	"fmt"
	"math/big"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/crypto/encproof"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"
)

var ProofParameter = crypto.NewProofConfig(tss.S256().Params().N)

func OnSignRound1Exec(key string) (result utils.TssExecResult) {
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
	msgWireBytes, _, err := r1msg1.WireBytes()
	if err != nil {
		common.Logger.Errorf("get r1msg1 wire bytes error: %s", key)
		result.Err = fmt.Sprintf("get r1msg1 wire bytes error: %s", key)
		return
	}
	round.temp.signRound1Message1s[i] = msgWireBytes

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
		msgWireBytes, _, err := r1msg2.WireBytes()
		if err != nil {
			common.Logger.Errorf("get r1msg2 wire bytes error: %s", key)
			result.Err = fmt.Sprintf("get r1msg2 wire bytes error: %s", key)
			return
		}
		round.temp.send.signRound1Message2s[j] = msgWireBytes
		if j == i {
			round.temp.signRound1Message2s[i] = msgWireBytes
		}
	}

	result.Ok = true
	result.MsgWireBytes = round.temp.signRound1Message1s[i]
	return result
}

func GetRound1Msg2(key string, to int) (result utils.TssExecResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}
	result.Ok = true
	result.MsgWireBytes = party.temp.send.signRound1Message2s[to]
	return
}

func OnSignRound1MsgAccept(key string, from int, msgWireBytes string) (result utils.TssResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	rMsgBytes, err := base64.StdEncoding.DecodeString(msgWireBytes)
	if err != nil {
		common.Logger.Errorf("msg error, r1msg1 base64 decode fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, r1msg1 base64 decode fail, err:%s", err.Error())
		return
	}

	msg, err := tss.ParseWireMsg(rMsgBytes)
	if err != nil {
		common.Logger.Errorf("msg error, parse wire r1msg1 fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, parse wire r1msg1 fail, err:%s", err.Error())
		return
	}

	if _, ok := msg.Content().(*SignRound1Message1); ok {
		party.temp.signRound1Message1s[from] = rMsgBytes
	} else if _, ok := msg.Content().(*SignRound1Message2); ok {
		party.temp.signRound1Message2s[from] = rMsgBytes
	} else {
		result.Err = "not SignRound1Message"
		return
	}
	result.Ok = true
	return
}

func OnSignRound1Finish(key string) (result utils.TssResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	for j, msg := range party.temp.signRound1Message2s {
		if len(msg) == 0 {
			result.Err = fmt.Sprintf("msg is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
