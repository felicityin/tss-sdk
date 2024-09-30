package keygen

import (
	"encoding/json"
	"fmt"
	"math/big"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto/schnorr"
	"tss-sdk/tss/tss"
)

func KeygenRound4Exec(key string) (result KeygenExecResult) {
	round, ok := Parties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	round.number = 4
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_4 start", i)

	for j, _ := range round.temp.kgRound3Messages {
		if j == i {
			continue
		}

		common.Logger.Debugf("round_4 calc challenge")
		challenge := common.RejectionSample(
			round.params.EC().Params().N,
			common.SHA512_256i_TAGGED(
				append(round.temp.ssid, round.temp.srid...),
				big.NewInt(int64(j)),
				round.data.PubXj[j].X(),
				round.data.PubXj[j].Y(),
				round.temp.payload[j].commitedA.X(),
				round.temp.payload[j].commitedA.Y(),
			),
		)

		common.Logger.Debugf("round_4 get proof")

		pMsg, err := tss.ParseWireMsg(round.temp.kgRound3Messages[j])
		if err != nil {
			common.Logger.Errorf("msg error, parse wire msg fail, err:%s", err.Error())
			result.Err = fmt.Sprintf("msg error, parse wire msg fail, err:%s", err.Error())
			return
		}

		schProof := schnorr.Proof{Proof: pMsg.Content().(*KGRound3Message).UnmarshalSchProof()}

		common.Logger.Debugf("round_4 verify proof")

		if !schProof.Verify(round.temp.payload[j].commitedA, round.data.PubXj[j], challenge) {
			common.Logger.Errorf("schnorr proof verify failed, party: %d", j)
			result.Err = fmt.Sprintf("schnorr proof verify failed, party: %d", j)
			return
		}
	}

	// Compute and SAVE the public key
	pubKey := round.data.PubXj[0]
	var err error
	for j, pubx := range round.data.PubXj {
		if j == 0 {
			continue
		}
		pubKey, err = pubKey.Add(pubx)
		if err != nil {
			common.Logger.Errorf("calc pubkey failed, party: %d", j)
			result.Err = fmt.Sprintf("calc pubkey failed, party: %d", j)
			return
		}
	}
	round.data.Pubkey = pubKey

	saveBytes, err := json.Marshal(round.data)
	if err != nil {
		common.Logger.Errorf("round_4 save err: %s", err.Error())
		result.Err = fmt.Sprintf("round_4 save err: %s", err.Error())
		return
	}

	common.Logger.Infof("party: %d, round_4 save", i)
	result.Ok = true
	result.MsgWireBytes = saveBytes
	return result
}
