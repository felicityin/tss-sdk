package tssdk

import (
	"strings"

	onsign "tss-sdk/tss/protocols/frost/sign"
)

func NewEddsaSignLocalParty(
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
	return toMpcRes(res)
}

func RemoveEddsaSignParty(key string) bool {
	return onsign.RemoveSignParty(key)
}

func EddsaSignRound1Exec(key string) *MpcExecResult {
	res := onsign.OnSignRound1Exec(key)
	return toMpcExecRes(res)
}

func EddsaSignRound1MsgAccept(key string, from int, msgWireBytes string) *MpcResult {
	res := onsign.OnSignRound1MsgAccept(key, from, msgWireBytes)
	return toMpcRes(res)
}

func EddsaSignRound1Finish(key string) *MpcResult {
	res := onsign.OnSignRound1Finish(key)
	return toMpcRes(res)
}

func EddsaSignRound2Exec(key string) *MpcExecResult {
	res := onsign.OnsignRound2Exec(key)
	return toMpcExecRes(res)
}

func EddsaSignRound2MsgAccept(key string, from int, msgWireBytes string) *MpcResult {
	res := onsign.OnSignRound2MsgAccept(key, from, msgWireBytes)
	return toMpcRes(res)
}

func EddsaSignRound2Finish(key string) *MpcResult {
	res := onsign.OnSignRound2Finish(key)
	return toMpcRes(res)
}

func EddsaSignFinalExec(key string) *MpcExecResult {
	res := onsign.OnsignRound3Exec(key)
	return toMpcExecRes(res)
}
