package keygen

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/tss"
)

func KeygenRound1Exec(key string) (result KeygenExecResult) {
	round, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
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
	msgWireBytes, _, err := msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", key)
		result.Err = fmt.Sprintf("get msg wire bytes error: %s", key)
		return
	}
	round.temp.kgRound1Messages[i] = msgWireBytes

	result.Ok = true
	result.MsgWireBytes = msgWireBytes
	return result
}

func KeygenRound1Accept(key string, from int, msgWireBytes string) (result KeygenResult) {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	rMsgBytes, err := base64.StdEncoding.DecodeString(msgWireBytes)
	if err != nil {
		common.Logger.Errorf("msg error, msg base64 decode fail, err: %s", err.Error())
		result.Err = fmt.Sprintf("msg error, msg base64 decode fail, err:%s", err.Error())
		return
	}
	party.temp.kgRound1Messages[from] = rMsgBytes

	msg, err := tss.ParseWireMsg(rMsgBytes)
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err: %s", err.Error())
		result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
		return
	}
	if _, ok := msg.Content().(*KGRound1Message); !ok {
		result.Err = fmt.Sprintf("not KGRound1Message, err: %s", err.Error())
		return
	}
	result.Ok = true
	return
}

func KeygenRound1Finish(key string) (result KeygenResult) {
	party, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	for j, msg := range party.temp.kgRound1Messages {
		if j == party.PartyID().Index {
			continue
		}
		if len(msg) == 0 {
			result.Err = fmt.Sprintf("msg is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
