package keygen

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto/pubkey"
	"tss-sdk/tss/crypto/schnorr"
	"tss-sdk/tss/protocols/utils"
)

func KeygenRound4Exec(sessionId string) (result utils.TssExecResult) {
	round, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}
	round.number = 4
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_4 start", i)

	for j, msg := range round.temp.kgRound3Messages {
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
				round.temp.commitedA[j].X(),
				round.temp.commitedA[j].Y(),
			),
		)

		common.Logger.Debugf("round_4 get proof")

		schProof := schnorr.Proof{Proof: msg.Content().(*TKgRound3Message).UnmarshalSchProof()}

		common.Logger.Debugf("round_4 verify proof")

		if !schProof.Verify(round.temp.commitedA[j], round.data.PubXj[j], challenge) {
			err := fmt.Sprintf("schnorr proof verify failed, party: %d", j)
			common.Logger.Error(err)
			result.Err = err
			return
		}
	}

	saveBytes, err := json.Marshal(round.data)
	if err != nil {
		common.Logger.Errorf("round_4 save err: %s", err.Error())
		result.Err = fmt.Sprintf("round_4 save err: %s", err.Error())
		return
	}

	pk, err := pubkey.EncodeEcdsaPk(round.data.Pubkey.X(), round.data.Pubkey.Y())
	if err != nil {
		result.Err = fmt.Sprintf("encode ecdsa pk err: %s", err.Error())
		return
	}

	common.Logger.Infof("party: %d, round_4 save", i)
	result.Ok = true
	result.Msg = saveBytes
	result.ChainCode = hex.EncodeToString(round.data.ChainCode.Bytes())
	result.Pubkey = pk
	return result
}
