package auxiliary

import (
	"encoding/json"
	"fmt"

	"tss-sdk/tss/common"
	"tss-sdk/tss/protocols/utils"
)

func AuxRound4Exec(key string) (result utils.TssExecResult) {
	round, err := GetParty(key)
	if err != nil {
		result.Err = err.Error()
		return
	}
	round.number = 4
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_4 start", i)

	for j, msg := range round.temp.auxRound3Messages {
		if j == i {
			continue
		}

		common.Logger.Debugf("round_4 get proof")

		msg, err := utils.ParseWireMsg(msg, "AuxRound3Message")
		if err != nil {
			result.Err = err.Error()
			return
		}
		r3msg := msg.Content().(*AuxRound3Message)

		// Verify mod proof
		modProof, err := r3msg.UnmarshalModProof()
		if err != nil {
			err = fmt.Errorf("[j: %d] unmarshal mod proof failed: %s", j, err.Error())
			common.Logger.Errorf("%s", err.Error())
			result.Err = err.Error()
			return
		}
		if err := modProof.Verify(round.temp.rho, round.save.PaillierPKs[j].N); err != nil {
			err = fmt.Errorf("[j: %d] mod proof verify failed: %s", j, err.Error())
			common.Logger.Errorf("%s", err.Error())
			result.Err = err.Error()
			return
		}

		// Verify fac proof
		facProof, err := r3msg.UnmarshalFacProof()
		if err != nil {
			err = fmt.Errorf("[j: %d] unmarshal fac proof failed", j)
			common.Logger.Errorf("%s", err.Error())
			result.Err = err.Error()
			return
		}

		if err := facProof.Verify(ProofParameter, round.temp.ssid, round.temp.rho,
			round.save.PaillierPKs[j].N, round.save.PedersenPKs[i]); err != nil {
			err = fmt.Errorf("verify prm proof failed, party: %d", j)
			common.Logger.Errorf("%s", err.Error())
			result.Err = err.Error()
			return
		}
	}

	common.Logger.Infof("party: %d, round_4 save", i)
	saveBytes, err := json.Marshal(round.save)
	if err != nil {
		err = fmt.Errorf("round_final save err: %s", err.Error())
		common.Logger.Errorf("%s", err.Error())
		result.Err = err.Error()
		return
	}
	result.Ok = true
	result.MsgWireBytes = saveBytes
	return result
}
