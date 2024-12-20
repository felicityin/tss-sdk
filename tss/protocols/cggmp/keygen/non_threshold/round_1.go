package keygen

import (
	"fmt"
	"math/big"
	"strconv"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/protocols/utils"
)

func KeygenRound1Exec(sessionId string) (result utils.TssExecResult) {
	round, ok := Parties[sessionId]
	if !ok {
		common.Logger.Errorf("party not found: %s", sessionId)
		result.Err = fmt.Sprintf("party not found: %s", sessionId)
		return
	}

	round.number = 1
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	common.Logger.Infof("party: %d, round_1 start", i)

	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	ssid, err := round.getSSID()
	if err != nil {
		result.Err = fmt.Sprintf("get ssid err: %s", err.Error())
		return
	}
	round.temp.ssid = ssid

	if round.data.PrivXi == nil {
		round.data.PrivXi = common.GetRandomPositiveInt(round.params.PartialKeyRand(), round.params.EC().Params().N)
	}
	if round.data.ChainCode == nil {
		round.temp.chainCode, _ = common.GetRandomBytes(round.params.Rand(), 32)
	} else {
		round.temp.chainCode = round.data.ChainCode.Bytes()
	}
	round.data.PubXj[i] = crypto.ScalarBaseMult(round.params.EC(), round.data.PrivXi)

	round.temp.tau = common.GetRandomPositiveInt(round.params.PartialKeyRand(), round.params.EC().Params().N)
	round.temp.commitedA = crypto.ScalarBaseMult(round.params.EC(), round.temp.tau)

	round.temp.u, _ = common.GetRandomBytes(round.params.Rand(), 32)
	round.temp.srid, _ = common.GetRandomBytes(round.params.Rand(), 32)

	ids := round.params.Parties().IDs().Keys()
	round.data.Ks = ids
	round.data.ShareID = ids[i]

	// Compute V_i
	hash := common.SHA512_256(
		ssid,
		[]byte(strconv.Itoa(i)),
		round.temp.srid,
		round.data.PubXj[i].X().Bytes(),
		round.data.PubXj[i].Y().Bytes(),
		round.temp.commitedA.X().Bytes(),
		round.temp.commitedA.Y().Bytes(),
		round.temp.u,
		round.temp.chainCode,
	)

	common.Logger.Infof("party: %d, round_1 broadcast", i)

	msg := NewKGRound1Message(round.PartyID(), hash)
	msgWireBytes, router, err := msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", err.Error())
		result.Err = fmt.Sprintf("get msg wire bytes error: %s", err.Error())
		return
	}
	round.temp.kgRound1Messages[i] = msg

	result.Ok = true
	result.Msg = utils.MpcBroadcastMsg(round.sessionId, round.sessionKind, router, msgWireBytes)
	return result
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
		common.Logger.Errorf("parse recv msg err: %s", err.Error())
		result.Err = err.Error()
		return
	}

	if _, ok := msg.Content().(*KGRound1Message); !ok {
		result.Err = fmt.Sprintf("not KGRound1Message, err: %s", err.Error())
		return
	}

	result.Ok = true
	party.temp.kgRound1Messages[router.From.Index] = msg
	return
}

func KeygenRound1Finish(sessionId string) (result utils.TssResult) {
	party, ok := Parties[sessionId]
	if !ok {
		common.Logger.Errorf("party not found: %s", sessionId)
		result.Err = fmt.Sprintf("party not found: %s", sessionId)
		return
	}

	for j, msg := range party.temp.kgRound1Messages {
		if j == party.PartyID().Index {
			continue
		}
		if msg == nil {
			result.Err = fmt.Sprintf("r1msg is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
