package keygen

import (
	"bytes"
	"fmt"
	"math/big"
	"strconv"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/crypto/alice/utils"
	"tss-sdk/tss/crypto/commitments"
	"tss-sdk/tss/crypto/schnorr"
	"tss-sdk/tss/crypto/vss"
	u "tss-sdk/tss/protocols/utils"
)

func KeygenRound3Exec(sessionId string) (result u.TssExecResult) {
	round, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}
	round.number = 3
	round.resetOK()

	i := round.PartyID().Index
	common.Logger.Infof("party: %d, round_3 start", i)

	pjVss := make([]vss.Vs, round.params.PartyCount())
	xi := new(big.Int).Set(round.temp.shares[i].Share)

	for j, msg := range round.temp.kgRound2Message1s {
		if j == i {
			continue
		}

		r2msg1 := msg.Content().(*TKgRound2Message1)

		commitmentA, err := r2msg1.UnmarshalSchCommitment()
		if err != nil {
			err := fmt.Sprintf("[j: %d] unmalshal commitment failed", j)
			common.Logger.Error(err)
			result.Err = err
			return
		}
		round.temp.commitedA[j] = commitmentA

		KGDj := r2msg1.UnmarshalDeCommitment()
		cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.KGCs[j], D: KGDj}
		ok, flatPolyGs := cmtDeCmt.DeCommit()
		if !ok || flatPolyGs == nil {
			err := fmt.Sprintf("[j: %d] de-commitment verify failed", j)
			common.Logger.Error(err)
			result.Err = err
			return
		}

		PjVs, err := crypto.UnFlattenECPoints(round.params.EC(), flatPolyGs)
		if err != nil {
			err := fmt.Sprintf("[j: %d] UnFlattenECPoints err: %s", j, err.Error())
			common.Logger.Error(err)
			result.Err = err
			return
		}
		pjVss[j] = PjVs

		if !bytes.Equal(r2msg1.GetSsid(), round.temp.ssid) {
			err := fmt.Sprintf("[%d] payload.ssid != round.temp.ssid", j)
			common.Logger.Error(err)
			result.Err = err
			return
		}

		// Verify commited V_j
		common.Logger.Debugf("[j: %d]round_3, calc V", j)
		Vj := common.SHA512_256(
			r2msg1.GetSsid(),
			[]byte(strconv.Itoa(round.params.PartyCount())),
			[]byte(strconv.Itoa(j)),
			[]byte(strconv.Itoa(round.params.Threshold())),
			r2msg1.GetSrid(),
			cmtDeCmt.C.Bytes(),
			commitmentA.X().Bytes(),
			commitmentA.Y().Bytes(),
			r2msg1.GetU(),
			r2msg1.GetChainCode(),
		)
		if !bytes.Equal(Vj, round.temp.V[j]) {
			err := fmt.Sprintf("[j: %d] hash != V", j)
			common.Logger.Error(err)
			result.Err = err
			return
		}

		r2msg2 := round.temp.kgRound2Message2s[j].Content().(*TKgRound2Message2)
		share := r2msg2.UnmarshalShare()
		PjShare := vss.Share{
			Threshold: round.params.Threshold(),
			ID:        round.PartyID().KeyInt(),
			Share:     share,
		}
		if ok = PjShare.Verify(round.params.EC(), round.params.Threshold(), PjVs); !ok {
			err := fmt.Sprintf("[j: %d] vss verify failed", j)
			common.Logger.Error(err)
			result.Err = err
			return
		}

		// Calculate private key
		xi = xi.Add(xi, share)

		// Set srid as xor of all party's srid_j
		common.Logger.Debugf("[j: %d] round_3, calc srid", j)
		round.temp.srid = utils.Xor(round.temp.srid, r2msg1.GetSrid())
		round.temp.chainCode = utils.Xor(round.temp.chainCode, r2msg1.GetChainCode())
	}

	round.data.PrivXi = xi.Mod(xi, round.params.EC().Params().N)
	round.data.ChainCode = new(big.Int).SetBytes(round.temp.chainCode)

	// Ours
	Vc := make(vss.Vs, round.params.Threshold()+1)
	for c := range Vc {
		Vc[c] = round.temp.vs[c]
	}

	// Compute F(x)
	{
		var err error
		for j := 0; j < round.params.PartyCount(); j++ {
			if j == i {
				continue
			}
			PjVs := pjVss[j]
			for c := 0; c <= round.params.Threshold(); c++ {
				Vc[c], err = Vc[c].Add(PjVs[c])
				if err != nil {
					err := fmt.Sprintf("calc F(x) err: %s", err.Error())
					common.Logger.Error(err)
					result.Err = err
					return
				}
			}
		}
	}

	// Compute Xj for each Pj
	{
		var err error
		modQ := common.ModInt(round.params.EC().Params().N)
		bigXj := round.data.PubXj
		for j := 0; j < round.params.PartyCount(); j++ {
			Pj := round.params.Parties().IDs()[j]
			kj := Pj.KeyInt()
			BigXj := Vc[0]
			z := new(big.Int).SetInt64(int64(1))
			for c := 1; c <= round.params.Threshold(); c++ {
				z = modQ.Mul(z, kj)
				BigXj, err = BigXj.Add(Vc[c].ScalarMult(z))
				if err != nil {
					err := fmt.Sprintf("adding Vc[c].ScalarMult(z) to BigXj resulted in a point not on the curve")
					common.Logger.Error(err)
					result.Err = err
					return
				}
			}
			bigXj[j] = BigXj
		}
		round.data.PubXj = bigXj
	}

	// Compute and save the public key
	pubKey, err := crypto.NewECPoint(round.params.EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		err := fmt.Sprintf("public key is not on the curve: %s", err.Error())
		common.Logger.Error(err)
		result.Err = err
		return
	}
	round.data.Pubkey = pubKey

	common.Logger.Debugf("party: %d, round_3, calc challenge", i)
	challenge := common.RejectionSample(
		round.params.EC().Params().N,
		common.SHA512_256i_TAGGED(
			append(round.temp.ssid, round.temp.srid...),
			big.NewInt(int64(i)),
			round.data.PubXj[i].X(),
			round.data.PubXj[i].Y(),
			round.temp.commitedA[i].X(),
			round.temp.commitedA[i].Y(),
		),
	)

	// Generate schnorr proof
	common.Logger.Debugf("party: %d, round_3, calc schnorr proof", i)
	schProof := schnorr.Prove(round.params.EC().Params().N, round.temp.tau, challenge, round.data.PrivXi)

	// BROADCAST proofs
	common.Logger.Infof("party: %d, round_3 broadcast", i)
	{
		msg := NewKGRound3Message(round.PartyID(), schProof.Proof.Bytes())
		round.temp.kgRound3Messages[i] = msg

		msgWireBytes, router, err := msg.WireBytes()
		if err != nil {
			err := fmt.Sprintf("get msg wire bytes error: %s", err.Error())
			common.Logger.Error(err)
			result.Err = err
			return
		}

		result.Ok = true
		result.Msg = u.MpcBroadcastMsg(round.sessionId, round.sessionKind, router, msgWireBytes)
	}
	return
}

func KeygenRound3Accept(sessionId string, recv []byte) (result u.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	msg, router, err := u.ParseMpcMsg(recv, sessionId)
	if err != nil {
		common.Logger.Errorf("parse recv r2msg err: %s", err.Error())
		result.Err = err.Error()
		return
	}

	if _, ok := msg.Content().(*TKgRound3Message); !ok {
		result.Err = fmt.Sprintf("not TKgRound3Message, err: %s", err.Error())
		return
	}

	result.Ok = true
	party.temp.kgRound3Messages[router.From.Index] = msg
	common.Logger.Infof("[%s] KeygenRound3Accept recv msg from  %d", sessionId, router.From.Index)
	return
}

func KeygenRound3Finish(sessionId string) (result u.TssResult) {
	party, err := GetParty(sessionId)
	if err != nil {
		result.Err = err.Error()
		return
	}

	for j, msg := range party.temp.kgRound3Messages {
		if j == party.PartyID().Index {
			continue
		}
		if msg == nil {
			result.Err = fmt.Sprintf("r3msg is null: %d", j)
			return
		}
	}
	result.Ok = true
	return
}
