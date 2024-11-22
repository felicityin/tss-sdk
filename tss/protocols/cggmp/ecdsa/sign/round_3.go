package sign

import (
	"encoding/base64"
	"fmt"
	"math/big"
	sync "sync"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto/logproof"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"
)

func OnsignRound3Exec(key string) (result utils.TssResult) {
	round, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	round.number = 3
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("[sign] party: %d, round_3 start", i)

	// Γ = sum_j Γj
	sumGamma := round.temp.Gamma

	errChs := make(chan *tss.Error, (len(round.params.Parties().IDs())-1)*3)
	wg := sync.WaitGroup{}
	wg.Add((len(round.params.Parties().IDs()) - 1) * 2)

	// verify received proofs
	for j, Pj := range round.params.Parties().IDs() {
		if j == i {
			continue
		}

		contextJ := append(round.temp.ssid, big.NewInt(int64(j)).Bytes()...)

		pMsg, err := tss.ParseWireMsg(round.temp.signRound2Messages[j])
		if err != nil {
			common.Logger.Errorf("msg error, parse wire r2msg fail, err:%s", err.Error())
			result.Err = fmt.Sprintf("msg error, parse wire r2msg fail, err:%s", err.Error())
			return
		}
		r2msg := pMsg.Content().(*SignRound2Message)

		Gamma, err := r2msg.UnmarshalGamma()
		if err != nil {
			common.Logger.Errorf("msg error, unmarshal r2msg err: %s", err.Error())
			result.Err = fmt.Sprintf("msg error, unmarshal r2msg err: %s", err.Error())
			return
		}
		sumGamma, err = sumGamma.Add(Gamma)
		if err != nil {
			common.Logger.Errorf("sumGamma.Add(Gamma) err: %s", err.Error())
			result.Err = fmt.Sprintf("sumGamma.Add(Gamma) err: %s", err.Error())
			return
		}

		psiProof, err := r2msg.UnmarshalAffgProof()
		if err != nil {
			common.Logger.Errorf("[j: %d] failed to unmarshal affg proof: %s", j, err.Error())
			result.Err = fmt.Sprintf("[j: %d] failed to unmarshal affg proof: %s", j, err.Error())
			return
		}
		common.Logger.Debugf("P[%d]: receive P[%d]'s affg proof", i, j)

		psiHatProof, err := r2msg.UnmarshalAffgHatProof()
		if err != nil {
			common.Logger.Errorf("[j: %d] failed to unmarshal affg_hat proof: %s", j, err.Error())
			result.Err = fmt.Sprintf("[j: %d] failed to unmarshal affg_hat proof: %s", j, err.Error())
			return
		}
		common.Logger.Debugf("P[%d]: receive P[%d]'s affg_hat proof", i, j)

		logProof, err := r2msg.UnmarshalLogProof()
		if err != nil {
			common.Logger.Errorf("[j: %d] failed to unmarshal log proof: %s", j, err.Error())
			result.Err = fmt.Sprintf("[j: %d] failed to unmarshal log proof: %s", j, err.Error())
			return
		}
		common.Logger.Debugf("P[%d]: receive P[%d]'s log proof", i, j)

		go func(j int) {
			defer wg.Done()

			if err = psiProof.Verify(
				ProofParameter, contextJ, round.aux.PaillierPKs[i].N, round.aux.PedersenPKs[j].N, round.temp.kCiphertexts[i],
				new(big.Int).SetBytes(r2msg.GetD()), new(big.Int).SetBytes(r2msg.GetF()), round.aux.PedersenPKs[i], Gamma,
			); err != nil {
				common.Logger.Errorf("[j: %d] failed to verify affg proof: %s", j, err)
				errChs <- round.WrapError(fmt.Errorf("[j: %d] failed to verify affg proof: %s", j, err.Error()))
			}
		}(j)

		go func(j int) {
			defer wg.Done()

			if err = psiHatProof.Verify(
				ProofParameter, contextJ, round.aux.PaillierPKs[i].N, round.aux.PedersenPKs[j].N, round.temp.kCiphertexts[i],
				new(big.Int).SetBytes(r2msg.GetDHat()), new(big.Int).SetBytes(r2msg.GetFHat()), round.aux.PedersenPKs[i], round.key.PubXj[j],
			); err != nil {
				common.Logger.Errorf("[j: %d] failed to verify affg_hat proof: %s", j, err)
				errChs <- round.WrapError(fmt.Errorf("failed to verify affg_hat proof: %s", err.Error()), Pj)
			}

			if err := logProof.Verify(
				ProofParameter, contextJ, round.temp.gammaCiphertexts[j], round.aux.PaillierPKs[j].N,
				round.aux.PedersenPKs[i], Gamma, nil,
			); err != nil {
				common.Logger.Errorf("verify log proof failed: %s, party: %d", err, j)
				errChs <- round.WrapError(fmt.Errorf("verify log proof failed: %s", err), Pj)
			}
			common.Logger.Debugf("P[%d]: verify P[%d]'s log proof ok", i, j)
		}(j)
	}

	// Consume error channels; wait for goroutines
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0, len(round.params.Parties().IDs()))
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		result.Err = fmt.Sprintf("[j: %d] failed to calculate affg proof: %+v", culprits)
		return
	}

	round.temp.sumGamma = sumGamma

	// ∆i = Γ^ki
	round.temp.Delta = sumGamma.ScalarMult(round.temp.k)
	// δi = γi * ki + sum(αi,j + βi,j) mod q
	delta := new(big.Int).Mul(round.temp.gamma, round.temp.k)
	// χi = xi * ki + sum(α̂ i,j + β̂ i,j) mod q
	chi := new(big.Int).Mul(round.key.PrivXi, round.temp.k)

	// calculate δi, χi
	for j := range round.params.Parties().IDs() {
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

		alpha, err := round.aux.PaillierSK.Decrypt(new(big.Int).SetBytes(r2msg.GetD()))
		if err != nil {
			common.Logger.Errorf("[j: %d] failed to decrypt alpha: %s", j, err)
			result.Err = fmt.Sprintf("[j: %d] failed to decrypt alpha: %s", j, err.Error())
			return
		}

		alphaHat, err := round.aux.PaillierSK.Decrypt(new(big.Int).SetBytes(r2msg.GetDHat()))
		if err != nil {
			common.Logger.Errorf("[j: %d] failed to decrypt alpha_hat: %s", j, err)
			result.Err = fmt.Sprintf("[j: %d] failed to decrypt alpha_hat: %s", j, err.Error())
			return
		}

		delta.Add(delta, alpha)
		delta.Add(delta, round.temp.beta[j])
		delta.Mod(delta, round.params.EC().Params().N)

		chi.Add(chi, alphaHat)
		chi.Add(chi, round.temp.betaHat[j])
		chi.Mod(chi, round.params.EC().Params().N)
	}

	round.temp.delta = delta
	round.temp.chi = chi

	// P2P send log proof to Pj
	contextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)
	for j, Pj := range round.params.Parties().IDs() {
		if j == i {
			round.ok[j] = true
			continue
		}
		// log proof: M(prove, Πlog, (ssid, i), (Iε, Ki, ∆i, Γ); (ki, ρi))
		logProof, err := logproof.NewKnowExponentAndPaillierEncryption(
			ProofParameter, contextI, round.temp.k, round.temp.rho, round.temp.kCiphertexts[i],
			round.aux.PaillierPKs[i].N, round.aux.PedersenPKs[j], round.temp.Delta, sumGamma,
		)
		if err != nil {
			common.Logger.Errorf("[j: %d] create log proof failed: %s", j, err.Error())
			result.Err = fmt.Sprintf("[j: %d] create log proof failed: %s", j, err.Error())
			return
		}

		common.Logger.Debugf("P[%d]: send log proof to P[%d]", i, j)
		r3msg, err := NewSignRound3Message(Pj, round.PartyID(), delta, round.temp.Delta, logProof)
		if err != nil {
			result.Err = fmt.Sprintf("[j: %d] create r3msg failed: %s", j, err.Error())
			return
		}
		msgWireBytes, _, err := r3msg.WireBytes()
		if err != nil {
			common.Logger.Errorf("get msg wire bytes error: %s", key)
			result.Err = fmt.Sprintf("get msg wire bytes error: %s", key)
			return
		}
		round.temp.send.signRound3Messages[j] = msgWireBytes
		if j == i {
			round.temp.signRound3Messages[i] = msgWireBytes
		}
	}

	result.Ok = true
	return result
}

func GetRound3Msg(key string, to int) (result utils.TssExecResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}
	result.Ok = true
	result.MsgWireBytes = party.temp.send.signRound3Messages[to]
	return
}

func OnSignRound3MsgAccept(key string, from int, msgWireBytes string) (result utils.TssResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	rMsgBytes, err := base64.StdEncoding.DecodeString(msgWireBytes)
	if err != nil {
		common.Logger.Errorf("msg error, r3msg base64 decode fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, r3msg base64 decode fail, err:%s", err.Error())
		return
	}
	party.temp.signRound3Messages[from] = rMsgBytes

	msg, err := tss.ParseWireMsg(rMsgBytes)
	if err != nil {
		common.Logger.Errorf("msg error, parse wire r3msg fail, err:%s", err.Error())
		result.Err = fmt.Sprintf("msg error, parse wire r3msg fail, err:%s", err.Error())
		return
	}
	if _, ok := msg.Content().(*SignRound3Message); !ok {
		result.Err = "not SignRound3Message"
		return
	}

	result.Ok = true
	return
}

func OnSignRound3Finish(key string) (result utils.TssResult) {
	party, ok := SignParties[key]
	if !ok {
		common.Logger.Errorf("party not found: %s", key)
		result.Err = fmt.Sprintf("party not found: %s", key)
		return
	}

	for j, msg := range party.temp.signRound3Messages {
		if len(msg) == 0 {
			result.Err = fmt.Sprintf("r3msg is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
