package sign

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/agl/ed25519/edwards25519"
	edwards "github.com/decred/dcrd/dcrec/edwards/v2"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/tss"
)

func OnsignRound3Exec(key string) (result OnsignExecResult) {
	round, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}
	round.number = 3
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	common.Logger.Infof("[sign] party: %d, round_final start", i)

	sumS := round.temp.si

	for j, Pj := range round.params.Parties().IDs() {
		round.ok[j] = true
		if j == i {
			continue
		}

		pMsg, err := tss.ParseWireMsg(round.temp.signRound2Messages[j])
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
			result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
			return
		}
		r2msg := pMsg.Content().(*SignRound2Message)
		zi := r2msg.UnmarshalS()

		ziGx, ziGy := round.params.EC().ScalarBaseMult(zi.Bytes())
		ziG := crypto.NewECPointNoCurveCheck(round.params.EC(), ziGx, ziGy)

		tmp := round.keys.PubXj[j].ScalarMult(round.temp.c)
		tmp, err = tmp.Add(round.temp.Rj[j])
		if err != nil {
			common.Logger.Errorf("[%d] err: Rj + c * Xj", Pj.Index)
			result.Err = "err: err: Rj + c * Xj"
			return
		}

		if hex.EncodeToString(ziG.X().Bytes()) != hex.EncodeToString(tmp.X().Bytes()) ||
			hex.EncodeToString(ziG.Y().Bytes()) != hex.EncodeToString(tmp.Y().Bytes()) {
			common.Logger.Errorf("[%d] err: Zj != Rj + c * Xj", Pj.Index)
			result.Err = "err: Zj != Rj + c * Xj"
			return
		}

		sjBytes := bigIntToEncodedBytes(zi)
		var tmpSumS [32]byte
		edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), sjBytes)
		sumS = &tmpSumS
	}
	s := encodedBytesToBigInt(sumS)

	// save the signature for final output
	round.data.Signature = append(bigIntToEncodedBytes(round.temp.r)[:], bigIntToEncodedBytes(s)[:]...)
	round.data.R = round.temp.r.Bytes()
	round.data.S = s.Bytes()
	if round.temp.fullBytesLen == 0 {
		round.data.M = round.temp.m.Bytes()
	} else {
		var mBytes = make([]byte, round.temp.fullBytesLen)
		round.temp.m.FillBytes(mBytes)
		round.data.M = mBytes
	}

	pk := edwards.PublicKey{
		Curve: round.params.EC(),
		X:     round.keys.Pubkey.X(),
		Y:     round.keys.Pubkey.Y(),
	}

	if ok := edwards.Verify(&pk, round.data.M, round.temp.r, s); !ok {
		common.Logger.Errorf("sig verify failed")
		result.Err = "sig verify failed"
	}

	saveBytes, err := json.Marshal(round.data)
	if err != nil {
		common.Logger.Errorf("round_final save err: %s", err.Error())
		result.Err = fmt.Sprintf("round_final save err: %s", err.Error())
		return
	}

	common.Logger.Infof("party: %d, round 3 end", i)
	result.Ok = true
	result.MsgWireBytes = saveBytes
	return result
}
