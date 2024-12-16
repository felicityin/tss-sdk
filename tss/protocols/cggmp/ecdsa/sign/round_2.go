package sign

import (
	"fmt"
	"math/big"
	sync "sync"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/crypto/affproof"
	"tss-sdk/tss/crypto/alice/mta"
	"tss-sdk/tss/crypto/logproof"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"
)

func OnsignRound2Exec(sessionId string) (result utils.TssResult) {
	round, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	round.number = 2
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("[sign] party: %d, round_2 start", i)

	contextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)

	// Verify received enc proof
	for j := 0; j < len(round.temp.signRound1Message1s); j++ {
		if j == i {
			continue
		}

		r1msg1 := round.temp.signRound1Message1s[j].Content().(*SignRound1Message1)
		round.temp.kCiphertexts[j] = r1msg1.UnmarshalK()
		round.temp.gammaCiphertexts[j] = r1msg1.UnmarshalGamma()
		common.Logger.Debugf("P[%d]: receive P[%d]'s kCiphertext and gammaCiphertext", i, j)

		r1msg2 := round.temp.signRound1Message2s[j].Content().(*SignRound1Message2)
		encProof, err := r1msg2.UnmarshalEncProof()
		if err != nil {
			common.Logger.Errorf("unmarshal enc proof failed, party: %d", j)
			result.Err = fmt.Sprintf("unmarshal enc proof failed, party: %d", j)
			return
		}
		common.Logger.Debugf("P[%d]: receive P[%d]'s enc proof", i, j)

		if err := encProof.Verify(
			ProofParameter, contextI, round.temp.kCiphertexts[j],
			round.aux.PaillierPKs[j].N, round.aux.PedersenPKs[i],
		); err != nil {
			common.Logger.Errorf("verify enc proof failed, party: %d", j)
			result.Err = fmt.Sprintf("verify enc proof failed, party: %d", j)
			return
		}
		common.Logger.Debugf("P[%d]: verify P[%d]'s enc proof ok", i, j)
	}

	// Compute Gammai = gammai * G
	common.Logger.Debugf("P[%d]: calc Gammai", i)
	round.temp.Gamma = crypto.ScalarBaseMult(round.params.EC(), round.temp.gamma)

	var Ds = make([][]byte, len(round.params.Parties().IDs()))
	var Fs = make([]*big.Int, len(round.params.Parties().IDs()))
	var psiProofs = make([]*affproof.PaillierAffAndGroupRangeMessage, len(round.params.Parties().IDs()))
	var Dhats = make([][]byte, len(round.params.Parties().IDs()))
	var Fhats = make([]*big.Int, len(round.params.Parties().IDs()))
	var psiHatProofs = make([]*affproof.PaillierAffAndGroupRangeMessage, len(round.params.Parties().IDs()))

	errChs := make(chan *tss.Error, (len(round.params.Parties().IDs())-1)*2)
	wg := sync.WaitGroup{}
	wg.Add((len(round.params.Parties().IDs()) - 1) * 2)

	// Generates proofs for Pj
	for j, Pj := range round.params.Parties().IDs() {
		if j == i {
			round.ok[j] = true
			continue
		}

		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			// aff-g proof: M(prove, Πaff-g, (sid, i), (Iε, Jε, Dj,i, Kj, Fj,i, Gi); (gammai, βi,j, si,j, ri,j))
			negBeta, countDelta, r, s, D, F, psiProof, err := mta.MtaWithProofAff_g(
				round.params.Rand(), contextI, round.aux.PedersenPKs[j], round.aux.PaillierPKs[i],
				round.temp.kCiphertexts[j], round.temp.gamma, round.temp.Gamma,
			)
			Ds[j], Fs[j], psiProofs[j], round.temp.beta[j], _, _, _ = D, F, psiProof, negBeta, countDelta, r, s
			if err != nil {
				common.Logger.Errorf("create aff-g proof 1 failed: %s", err.Error())
				errChs <- round.WrapError(fmt.Errorf("create aff-g proof 1 failed: %s", err.Error()))
			}
		}(j, Pj)

		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			// aff-g proof: M(prove, Πaff-g, (sid, i), (Iε, Jε, Dˆj,i, Kj, Fˆj,i, Xi); (xi, βˆi,j, sˆi,j, rˆi,j))
			negBetaHat, countSigma, rhat, shat, Dhat, Fhat, psiHatProof, err := mta.MtaWithProofAff_g(
				round.params.Rand(), contextI, round.aux.PedersenPKs[j], round.aux.PaillierPKs[i],
				round.temp.kCiphertexts[j], round.key.PrivXi, round.key.PubXj[i],
			)
			Dhats[j], Fhats[j], psiHatProofs[j], round.temp.betaHat[j], _, _, _ = Dhat, Fhat, psiHatProof, negBetaHat, countSigma, rhat, shat
			if err != nil {
				common.Logger.Errorf("create aff-g proof 2 failed: %s", err.Error())
				errChs <- round.WrapError(fmt.Errorf("create aff-g proof 2 failed: %s", err.Error()))
			}
		}(j, Pj)
	}

	// Consume error channels; wait for goroutines
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0, len(round.params.Parties().IDs()))
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		common.Logger.Errorf("failed to calculate affg proof: %+v", culprits)
		result.Err = fmt.Sprintf("failed to calculate affg proof: %+v", culprits)
		return
	}

	for j, Pj := range round.params.Parties().IDs() {
		if j == i {
			continue
		}

		// log proof for the secret gamma, mu: M(prove, Πlog, (sid, i), (Iε, Gi, Γi, g); (γi, νi))
		logProof, err := logproof.NewKnowExponentAndPaillierEncryption(
			ProofParameter, contextI, round.temp.gamma, round.temp.mu, round.temp.gammaCiphertexts[i],
			round.aux.PaillierPKs[i].N, round.aux.PedersenPKs[j], round.temp.Gamma, nil,
		)
		if err != nil {
			common.Logger.Errorf("create log proof failed: %+v", culprits)
			result.Err = fmt.Sprintf("create log proof failed: %+v", culprits)
			return
		}

		common.Logger.Debugf("P[%d]: send proofs to P[%d]", i, j)
		r2msg, err := NewSignRound2Message(
			Pj, round.PartyID(), round.temp.Gamma, Ds[j], Fs[j], Dhats[j], Fhats[j], psiProofs[j], psiHatProofs[j], logProof,
		)
		if err != nil {
			common.Logger.Errorf("create r2msg failed: %+v", culprits)
			result.Err = fmt.Sprintf("create r2msg failed: %+v", culprits)
			return
		}
		msgWireBytes, router, err := r2msg.WireBytes()
		if err != nil {
			common.Logger.Errorf("get msg wire bytes error: %s", sessionId)
			result.Err = fmt.Sprintf("get msg wire bytes error: %s", sessionId)
			return
		}
		round.temp.send.signRound2Messages[j] = utils.MpcP2pMsg(round.sessionId, round.sessionKind, Pj.Id, router, msgWireBytes)
		if j == i {
			round.temp.signRound2Messages[i] = r2msg
		}
	}

	result.Ok = true
	return result
}

func GetRound2Msg(sessionId string, toDeviceId string) (result utils.TssExecResult) {
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
	result.Msg = party.temp.send.signRound2Messages[to]
	return
}

func OnSignRound2MsgAccept(sessionId string, recv []byte) (result utils.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	msg, from, err := utils.ParseMpcMsg(recv, sessionId)
	if err != nil {
		common.Logger.Errorf("parse recv r2msg err: %s", err.Error())
		result.Err = err.Error()
		return
	}

	if _, ok := msg.Content().(*SignRound2Message); !ok {
		result.Err = "not SignRound2Message"
		return
	}

	result.Ok = true
	party.temp.signRound2Messages[from] = msg
	return
}

func OnSignRound2Finish(sessionId string) (result utils.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	for j, msg := range party.temp.signRound2Messages {
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
