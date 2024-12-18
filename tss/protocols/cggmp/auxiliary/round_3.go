package auxiliary

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto/alice/utils"
	"tss-sdk/tss/crypto/facproof"
	"tss-sdk/tss/crypto/modproof"
	"tss-sdk/tss/crypto/prmproof"
	u "tss-sdk/tss/protocols/utils"
)

func AuxRound3Exec(sessionId string) (result u.TssResult) {
	round, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}
	round.number = 3
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_3 start", i)

	for j, msg := range round.temp.auxRound2Messages {
		if j == i {
			continue
		}

		r2Msg := msg.Content().(*AuxRound2Message)

		if !bytes.Equal(r2Msg.GetSsid(), round.temp.ssid) {
			err = fmt.Errorf("[j: %d] payload.ssid != round.temp.ssid", j)
			common.Logger.Errorf("%s", err.Error())
			result.Err = err.Error()
			return
		}

		round.save.PaillierPKs[j] = r2Msg.UnmarshalPaillierPK()
		round.save.PedersenPKs[j] = r2Msg.UnmarshalPedersenPK()

		// Verify prm proof
		prmProof, err := r2Msg.UnmarshalPrmProof()
		if err != nil {
			err = fmt.Errorf("[j: %d] unmarshal prm proof failed", j)
			common.Logger.Errorf("%s", err.Error())
			result.Err = err.Error()
			return
		}
		if err := round.verifyPrmPubsessionIds(j, prmProof); err != nil {
			err = fmt.Errorf("verifyPrmPubsessionIds err: %s", err.Error())
			common.Logger.Errorf("%s", err.Error())
			result.Err = err.Error()
			return
		}
		contextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
		if err := prmProof.Verify(contextJ); err != nil {
			err = fmt.Errorf("[j: %d] verify prm proof failed: %s", j, err.Error())
			common.Logger.Errorf("%s", err.Error())
			result.Err = err.Error()
			return
		}

		common.Logger.Debugf("party: %d, round_3, calc V", i)
		hash := common.SHA512_256(
			round.temp.ssid,
			[]byte(strconv.Itoa(j)),
			r2Msg.GetSrid(),
			round.save.PaillierPKs[j].N.Bytes(),
			round.save.PedersenPKs[j].S.Bytes(),
			round.save.PedersenPKs[j].T.Bytes(),
			prmProof.Salt,
			r2Msg.GetRho(),
			r2Msg.GetU(),
		)

		// Verify commited V_i
		if !bytes.Equal(hash, round.temp.V[j]) {
			err = fmt.Errorf("[j: %d] hash != V", j)
			common.Logger.Errorf("%s", err.Error())
			result.Err = err.Error()
			return
		}

		// Set rho as xor of all party's rho_i
		common.Logger.Debugf("party: %d, round_3, calc rho", i)
		round.temp.rho = utils.Xor(round.temp.rho, r2Msg.GetRho())
	}

	// Generate mod proof
	modProof, err := modproof.NewPaillierBlumMessage(
		round.temp.rho, round.save.PaillierSK.P, round.save.PaillierSK.Q, round.save.PedersenPKs[i].GetN(), modproof.MINIMALCHALLENGE,
	)
	if err != nil {
		err = fmt.Errorf("party %d, calc mod proof failed: %s", i, err.Error())
		common.Logger.Errorf("%s", err.Error())
		result.Err = err.Error()
		return
	}

	// P2P send proofs
	for j, Pj := range round.params.Parties().IDs() {
		if j == i {
			round.ok[j] = true
			continue
		}

		facProof, err := facproof.NewNoSmallFactorMessage(
			ProofParameter,
			round.temp.ssid,
			round.temp.rho,
			round.save.PaillierSK.P,
			round.save.PaillierSK.Q,
			round.save.PaillierPKs[i].N,
			round.save.PedersenPKs[j],
		)
		if err != nil {
			err = fmt.Errorf("[j: %d] calc fac proof failed: %s", j, err.Error())
			common.Logger.Errorf("%s", err.Error())
			result.Err = err.Error()
			return
		}

		common.Logger.Debugf("P[%d]: send fac proof to P[%d]", i, j)
		r3msg, err := NewAuxRound3Message(Pj, round.PartyID(), facProof, modProof)
		if err != nil {
			err = fmt.Errorf("[j: %d] create aux round3 msg err: %s", j, err.Error())
			common.Logger.Errorf("%s", err.Error())
			result.Err = err.Error()
			return
		}
		msgWireBytes, router, err := r3msg.WireBytes()
		if err != nil {
			err = fmt.Errorf("get msg wire bytes error: %s", sessionId)
			common.Logger.Errorf("%s", err.Error())
			result.Err = err.Error()
			return
		}
		round.temp.send.auxRound3Messages[j] = u.MpcP2pMsg(round.sessionId, round.sessionKind, Pj.Id, router, msgWireBytes)
		if j == i {
			round.temp.auxRound3Messages[i] = r3msg
		}
	}
	result.Ok = true
	return result
}

func (round *LocalParty) verifyPrmPubsessionIds(j int, msg *prmproof.RingPederssenParameterMessage) error {
	n := new(big.Int).SetBytes(msg.N)
	s := new(big.Int).SetBytes(msg.S)
	t := new(big.Int).SetBytes(msg.T)

	if n.Cmp(round.save.PedersenPKs[j].N) != 0 {
		common.Logger.Errorf("msg.N != save.N, party: %d, msg.N = %d, save.N = %d", j, n, round.save.PedersenPKs[j].N)
		return errors.New("msg.N != save.N")
	}

	if s.Cmp(round.save.PedersenPKs[j].S) != 0 {
		common.Logger.Errorf("msg.S != save.S, party: %d", j)
		return errors.New("msg.S != save.S")
	}

	if t.Cmp(round.save.PedersenPKs[j].T) != 0 {
		common.Logger.Errorf("msg.T != save.T, party: %d", j)
		return errors.New("msg.T != save.T")
	}
	return nil
}

func GetRound3Msg(sessionId string, toDeviceId string) (result u.TssExecResult) {
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
	result.Msg = party.temp.send.auxRound3Messages[to]
	return
}

func AuxRound3Accept(sessionId string, recv []byte) (result u.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	msg, router, err := u.ParseMpcMsg(recv, sessionId)
	if err != nil {
		common.Logger.Errorf("parse recv msg err: %s", err.Error())
		result.Err = err.Error()
		return
	}
	party.temp.auxRound3Messages[router.From.Index] = msg

	if _, ok := msg.Content().(*AuxRound3Message); !ok {
		err := fmt.Errorf("not AuxRound3Message")
		common.Logger.Errorf("%s", err.Error())
		result.Err = err.Error()
		return
	}
	result.Ok = true
	return
}

func AuxRound3Finish(sessionId string) (result u.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	for j, msg := range party.temp.auxRound3Messages {
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
