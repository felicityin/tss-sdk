package auxiliary

import (
	"fmt"
	"math/big"
	"strconv"

	"tss-sdk/tss/common"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/crypto/prmproof"
	"tss-sdk/tss/protocols/utils"
	"tss-sdk/tss/tss"
)

var ProofParameter = crypto.NewProofConfig(tss.S256().Params().N)

func AuxRound1Exec(key string) (result utils.TssExecResult) {
	round, err := GetParty(key)
	if err != nil {
		result.Err = err.Error()
		return
	}

	round.number = 1
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	common.Logger.Infof("party: %d, round_1 start", i)

	ids := round.params.Parties().IDs().Keys()
	round.save.Ks = ids
	round.save.ShareID = ids[i]

	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	ssid, err := round.getSSID()
	if err != nil {
		result.Err = fmt.Sprintf("get ssid err: %s", err.Error())
		return
	}
	round.temp.ssid = ssid

	if round.save.PaillierSK == nil {
		round.save.PaillierSK, err = GeneratePaillier(round.params.Rand())
		if err != nil {
			err = fmt.Errorf("paillier sk generation failed: %s", err.Error())
			common.Logger.Errorf("%s", err.Error())
			result.Err = err.Error()
			return
		}
	}
	round.save.PaillierPKs[i] = &round.save.PaillierSK.PublicKey

	// Set pedersen parameter from paillierKey: Sample r in Z_N^ast, lambda = Z_phi(N), t = r^2 and s = t^lambda mod N
	pedersen, err := round.save.PaillierSK.NewPedersenParameterByPaillier()
	if err != nil {
		err = fmt.Errorf("generate ring-pedersen keys failed: %s", err.Error())
		common.Logger.Errorf("%s", err.Error())
		result.Err = err.Error()
		return
	}
	round.save.PedersenPKs[i] = pedersen.PedersenOpenParameter

	// Generate prm proof
	contextI := append(round.temp.ssid, big.NewInt(int64(i)).Bytes()...)
	prmProof, err := prmproof.NewRingPederssenParameterMessage(
		contextI,
		pedersen.GetEulerValue(),
		pedersen.PedersenOpenParameter.GetN(),
		pedersen.PedersenOpenParameter.GetS(),
		pedersen.PedersenOpenParameter.GetT(),
		pedersen.Getlambda(),
		prmproof.MINIMALCHALLENGE,
	)
	if err != nil {
		err = fmt.Errorf("party: %d, generate prm proof error: %s", i, err.Error())
		common.Logger.Errorf("%s", err.Error())
		result.Err = err.Error()
		return
	}
	round.temp.prmProof = prmProof

	round.temp.u, _ = common.GetRandomBytes(round.params.Rand(), 32)
	round.temp.rho, _ = common.GetRandomBytes(round.params.Rand(), 32)
	round.temp.srid, _ = common.GetRandomBytes(round.params.Rand(), 32)

	// Compute V_i
	hash := common.SHA512_256(
		ssid,
		[]byte(strconv.Itoa(i)),
		round.temp.srid,
		round.save.PaillierPKs[i].N.Bytes(),
		round.save.PedersenPKs[i].S.Bytes(),
		round.save.PedersenPKs[i].T.Bytes(),
		prmProof.Salt,
		round.temp.rho,
		round.temp.u,
	)

	common.Logger.Infof("party: %d, round_1 broadcast", i)

	msg := NewAuxRound1Message(round.PartyID(), hash)
	msgWireBytes, _, err := msg.WireBytes()
	if err != nil {
		err = fmt.Errorf("get msg wire bytes error: %s", err.Error())
		common.Logger.Errorf("%s", err.Error())
		result.Err = err.Error()
		return
	}
	round.temp.auxRound1Messages[i] = msg

	result.Ok = true
	result.MsgWireBytes = msgWireBytes
	return result
}

func AuxRound1Accept(key string, from int, msgWireBytes string) (result utils.TssResult) {
	party, err := GetParty(key)
	if err != nil {
		result.Err = err.Error()
		return
	}

	msg, err := utils.ParseRecvMsg(msgWireBytes)
	if err != nil {
		result.Err = err.Error()
		return
	}

	if _, ok := msg.Content().(*AuxRound1Message); !ok {
		err := fmt.Errorf("not AuxRound1Message")
		common.Logger.Errorf("%s", err.Error())
		result.Err = err.Error()
		return
	}
	result.Ok = true
	party.temp.auxRound1Messages[from] = msg
	return
}

func AuxRound1Finish(key string) (result utils.TssResult) {
	party, err := GetParty(key)
	if err != nil {
		result.Err = err.Error()
		return
	}

	for j, msg := range party.temp.auxRound1Messages {
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
