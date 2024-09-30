package tsssdk

import (
	"strings"

	onsign "tss-sdk/tss/protocols/frost/sign"
)

func NewSignLocalParty(
	key string,
	partyIndex int,
	partyCount int,
	pIDs string,
	msg string, // hex string
	keyData string, // keygen.LocalPartySaveData, base64 string
	walletPath string,
) *MpcResult {
	ids := strings.Split(pIDs, ",")
	res := onsign.NewLocalParty(false, key, partyIndex, partyCount, ids, msg, keyData, walletPath)
	return resFromOnsign(res)
}

func RemoveSignParty(key string) bool {
	return onsign.RemoveSignParty(key)
}

func OnSignRound1Exec(key string) *MpcExecResult {
	res := onsign.OnSignRound1Exec(key)
	return execResFromOnsign(res)
}

func OnSignRound1MsgAccept(key string, from int, msgWireBytes string) *MpcResult {
	res := onsign.OnSignRound1MsgAccept(key, from, msgWireBytes)
	return resFromOnsign(res)
}

func OnSignRound1Finish(key string) *MpcResult {
	res := onsign.OnSignRound1Finish(key)
	return resFromOnsign(res)
}

func OnSignRound2Exec(key string) *MpcExecResult {
	res := onsign.OnsignRound2Exec(key)
	return execResFromOnsign(res)
}

func OnSignRound2MsgAccept(key string, from int, msgWireBytes string) *MpcResult {
	res := onsign.OnSignRound2MsgAccept(key, from, msgWireBytes)
	return resFromOnsign(res)
}

func OnSignRound2Finish(key string) *MpcResult {
	res := onsign.OnSignRound2Finish(key)
	return resFromOnsign(res)
}

func OnSignFinalExec(key string) *MpcExecResult {
	res := onsign.OnsignRound3Exec(key)
	return execResFromOnsign(res)
}

func execResFromOnsign(res onsign.OnsignExecResult) *MpcExecResult {
	return &MpcExecResult{
		Ok:           res.Ok,
		Err:          res.Err,
		MsgWireBytes: res.MsgWireBytes,
	}
}

func resFromOnsign(res onsign.OnsignResult) *MpcResult {
	return &MpcResult{
		Ok:  res.Ok,
		Err: res.Err,
	}
}
