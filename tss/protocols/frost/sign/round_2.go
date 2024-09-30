package sign

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"

	"github.com/agl/ed25519/edwards25519"
	"google.golang.org/protobuf/proto"

	"tss-sdk/tss/common"
	"tss-sdk/tss/tss"
)

func OnsignRound2Exec(key string) (result OnsignExecResult) {
	round, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	round.number = 2
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("[sign] party: %d, round_2 start", i)

	var B []byte

	for j, _ := range round.params.Parties().IDs() {
		pMsg, err := tss.ParseWireMsg(round.temp.signRound1Messages[j])
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg1 err: %s", err.Error())
			result.Err = fmt.Sprintf("msg error, parse wire msg1 err: %s", err.Error())
			return
		}
		r1msg := pMsg.Content().(*SignRound1Message)

		bs, err := proto.Marshal(r1msg)
		if err != nil {
			common.Logger.Errorf("marshal round1 msg err: %s", err.Error())
			result.Err = fmt.Sprintf("marshal round1 msg err: %s", err.Error())
			return
		}

		B = append(B, round.keys.PubXj[j].X().Bytes()...)
		B = append(B, bs...)
	}

	rhoi := new(big.Int).SetBytes(
		common.SHA512_256([]byte(strconv.Itoa(i)), round.temp.m.Bytes(), common.SHA512_256(B)),
	)
	rhoi.Mod(rhoi, round.params.EC().Params().N)

	ki := new(big.Int).Mul(round.temp.e, rhoi)
	ki.Add(ki, round.temp.d)
	ki.Mod(ki, round.params.EC().Params().N)

	var R edwards25519.ExtendedGroupElement
	riBytes := bigIntToEncodedBytes(ki)
	edwards25519.GeScalarMultBase(&R, riBytes)

	for j, _ := range round.params.Parties().IDs() {
		if j == i {
			continue
		}

		rhoj := new(big.Int).SetBytes(
			common.SHA512_256([]byte(strconv.Itoa(j)), round.temp.m.Bytes(), common.SHA512_256(B)),
		)
		rhoj.Mod(rhoj, round.params.EC().Params().N)

		pMsg, err := tss.ParseWireMsg(round.temp.signRound1Messages[j])
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg1 err: %s", err.Error())
			result.Err = fmt.Sprintf("msg error, parse wire msg1 err: %s", err.Error())
			return
		}
		r1msg := pMsg.Content().(*SignRound1Message)

		D, err := r1msg.UnmarshalD()
		if err != nil {
			common.Logger.Errorf("failed to unmarshal D: %s, party: %d", err, j)
			result.Err = fmt.Sprintf("failed to unmarshal D: %s, party: %d", err, j)
			return
		}

		E, err := r1msg.UnmarshalE()
		if err != nil {
			common.Logger.Errorf("failed to unmarshal E: %s, party: %d", err, j)
			result.Err = fmt.Sprintf("failed to unmarshal E: %s, party: %d", err, j)
			return
		}

		Rj, err := E.ScalarMult(rhoj).Add(D)
		if err != nil {
			common.Logger.Errorf("rho * E + D err: %s", err.Error())
			result.Err = fmt.Sprintf("rho * E + D err: %s", err.Error())
			return
		}
		round.temp.Rj[j] = Rj

		Rj = Rj.EightInvEight()
		if err != nil {
			common.Logger.Errorf("NewECPoint(Rj) err: %s", err.Error())
			result.Err = fmt.Sprintf("NewECPoint(Rj) err: %s", err.Error())
			return
		}

		extendedRj := ecPointToExtendedElement(round.params.EC(), Rj.X(), Rj.Y(), round.params.Rand())
		R = addExtendedElements(R, extendedRj)
	}

	// compute lambda
	var encodedR [32]byte
	R.ToBytes(&encodedR)

	encodedPubKey := ecPointToEncodedBytes(round.keys.Pubkey.X(), round.keys.Pubkey.Y())

	// h = hash512(R || X || M)
	h := sha512.New()
	h.Reset()
	h.Write(encodedR[:])
	h.Write(encodedPubKey[:])
	if round.temp.fullBytesLen == 0 {
		h.Write(round.temp.m.Bytes())
	} else {
		var mBytes = make([]byte, round.temp.fullBytesLen)
		round.temp.m.FillBytes(mBytes)
		h.Write(mBytes)
	}

	var lambda [64]byte
	h.Sum(lambda[:0])
	var lambdaReduced [32]byte
	edwards25519.ScReduce(&lambdaReduced, &lambda)

	// compute si
	var localS [32]byte
	edwards25519.ScMulAdd(&localS, &lambdaReduced, bigIntToEncodedBytes(round.keys.PrivXi), riBytes)

	round.temp.c = encodedBytesToBigInt(&lambdaReduced)
	round.temp.si = &localS
	round.temp.r = encodedBytesToBigInt(&encodedR)

	// broadcast si to other parties
	common.Logger.Debugf("P[%d]: round_2 broadcast", i)
	msg := NewSignRound2Message(round.PartyID(), encodedBytesToBigInt(&localS))
	msgWireBytes, _, err := msg.WireBytes()
	if err != nil {
		common.Logger.Errorf("get msg wire bytes error: %s", key)
		result.Err = fmt.Sprintf("get msg wire bytes error: %s", key)
		return
	}
	round.temp.signRound2Messages[i] = msgWireBytes

	result.Ok = true
	result.MsgWireBytes = msgWireBytes
	return result
}

func OnSignRound2MsgAccept(key string, from int, msgWireBytes string) (result OnsignResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	rMsgBytes, err := base64.StdEncoding.DecodeString(msgWireBytes)
	if err != nil {
		common.Logger.Errorf("msg error, msg base64 decode fail, err: %s", err.Error())
		result.Err = fmt.Sprintf("msg error, msg base64 decode fail, err: %s", err.Error())
		return
	}
	party.temp.signRound2Messages[from] = rMsgBytes

	msg, err := tss.ParseWireMsg(rMsgBytes)
	if err != nil {
		common.Logger.Errorf("msg error, parse wire msg fail, err: %s", err.Error())
		result.Err = fmt.Sprintf("msg error, parse wire msg fail, err: %s", err.Error())
		return
	}
	if _, ok := msg.Content().(*SignRound2Message); !ok {
		result.Err = "not SignRound2Message"
		return
	}

	result.Ok = true
	return
}

func OnSignRound2Finish(key string) (result OnsignResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = "not SignRound1Message2"
		return
	}

	for j, msg := range party.temp.signRound2Messages {
		if len(msg) == 0 {
			result.Err = fmt.Sprintf("msg is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
