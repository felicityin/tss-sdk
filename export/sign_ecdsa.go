package tssdk

import (
	"strings"

	onsign "tss-sdk/tss/protocols/cggmp/ecdsa/sign"
)

func NewEcdsaSignLocalParty(
	key string,
	partyIndex int,
	partyCount int,
	pIDs string,
	msg string, // hex string
	keyData string, // keygen.LocalPartySaveData, base64 string
	auxData string, // auxiliary.LocalPartySaveData, base64 string
	walletPath string,
) *MpcResult {
	ids := strings.Split(pIDs, ",")
	res := onsign.NewLocalParty(false, key, partyIndex, partyCount, ids, msg, keyData, auxData, walletPath)
	return toMpcRes(res)
}

func RemoveEcdsaSignParty(key string) bool {
	return onsign.RemoveSignParty(key)
}

func EcdsaSignRound1Exec(key string) *MpcExecResult {
	res := onsign.OnSignRound1Exec(key)
	return toMpcExecRes(res)
}

func GetSignRound1Msg2(key string, to int) *MpcExecResult {
	res := onsign.GetRound1Msg2(key, to)
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

func EcdsaSignRound2Exec(key string) *MpcResult {
	res := onsign.OnsignRound2Exec(key)
	return toMpcRes(res)
}

func GetSignRound2Msg(key string, to int) *MpcExecResult {
	res := onsign.GetRound2Msg(key, to)
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

func EcdsaSignRound3Exec(key string) *MpcResult {
	res := onsign.OnsignRound3Exec(key)
	return toMpcRes(res)
}

func GetSignRound3Msg(key string, to int) *MpcExecResult {
	res := onsign.GetRound3Msg(key, to)
	return toMpcExecRes(res)
}

func EcdsaSignRound3MsgAccept(key string, from int, msgWireBytes string) *MpcResult {
	res := onsign.OnSignRound3MsgAccept(key, from, msgWireBytes)
	return toMpcRes(res)
}

func EcdsaSignRound3Finish(key string) *MpcResult {
	res := onsign.OnSignRound3Finish(key)
	return toMpcRes(res)
}

func EcdsaSignRound4Exec(key string) *MpcExecResult {
	res := onsign.OnsignRound4Exec(key)
	return toMpcExecRes(res)
}

func EcdsaSignRound4MsgAccept(key string, from int, msgWireBytes string) *MpcResult {
	res := onsign.OnSignRound4MsgAccept(key, from, msgWireBytes)
	return toMpcRes(res)
}

func EcdsaSignRound4Finish(key string) *MpcResult {
	res := onsign.OnSignRound4Finish(key)
	return toMpcRes(res)
}

func EcdsaSignFinalExec(key string) *MpcResult {
	res := onsign.OnsignRound3Exec(key)
	return toMpcRes(res)
}
