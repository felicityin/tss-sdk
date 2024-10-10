package tssdk

import (
	"strings"

	onsign "tss-sdk/tss/protocols/frost/sign"
)

func NewEcdsaSignLocalParty(
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

func RemoveEcdsaSignParty(key string) bool {
	return onsign.RemoveSignParty(key)
}

func EcdsaSignRound1Exec(key string) *MpcExecResult {
	res := onsign.OnSignRound1Exec(key)
	return toMpcExecRes(res)
}

func EcdsaSignRound1MsgAccept(key string, from int, msgWireBytes string) *MpcResult {
	res := onsign.OnSignRound1MsgAccept(key, from, msgWireBytes)
	return toMpcRes(res)
}

func EcdsaSignRound1Finish(key string) *MpcResult {
	res := onsign.OnSignRound1Finish(key)
	return toMpcRes(res)
}

func EcdsaSignRound2Exec(key string) *MpcExecResult {
	res := onsign.OnsignRound2Exec(key)
	return toMpcExecRes(res)
}

func EcdsaSignRound2MsgAccept(key string, from int, msgWireBytes string) *MpcResult {
	res := onsign.OnSignRound2MsgAccept(key, from, msgWireBytes)
	return toMpcRes(res)
}

func EcdsaSignRound2Finish(key string) *MpcResult {
	res := onsign.OnSignRound2Finish(key)
	return toMpcRes(res)
}

func EcdsaSignFinalExec(key string) *MpcExecResult {
	res := onsign.OnsignRound3Exec(key)
	return toMpcExecRes(res)
}
