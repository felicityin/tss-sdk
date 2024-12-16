package tssdk

import (
	onsign "tss-sdk/tss/protocols/cggmp/ecdsa/sign"
)

func NewEcdsaSignLocalParty(
	isThreshold bool,
	sessionId string,
	sessionKind string,
	deviceId string,
	allDevices string, // comma separated
	connIds string, // comma separated
	msg string, // hex string
	keyData string, // keygen.LocalPartySaveData, base64 string
	auxData string, // auxiliary.LocalPartySaveData, base64 string
	walletPath string,
) *MpcResult {
	parties, connectIds, err := parseParties(allDevices, connIds)
	if err != nil {
		return &MpcResult{Ok: false, Err: err.Error()}
	}

	res := onsign.NewLocalParty(isThreshold, sessionId, sessionKind, deviceId, parties, connectIds, msg, keyData, auxData, walletPath)
	return toMpcRes(res)
}

func RemoveEcdsaSignParty(sessionId string) bool {
	return onsign.RemoveSignParty(sessionId)
}

func EcdsaSignRound1Exec(sessionId string) *MpcExecResult {
	res := onsign.OnSignRound1Exec(sessionId)
	return toMpcExecRes(res)
}

func GetSignRound1Msg2(sessionId string, toDeviceId string) *MpcExecResult {
	res := onsign.GetRound1Msg2(sessionId, toDeviceId)
	return toMpcExecRes(res)
}

func EcdsaSignRound1MsgAccept(sessionId string, recv []byte) *MpcResult {
	res := onsign.OnSignRound1MsgAccept(sessionId, recv)
	return toMpcRes(res)
}

func EcdsaSignRound1Finish(sessionId string) *MpcResult {
	res := onsign.OnSignRound1Finish(sessionId)
	return toMpcRes(res)
}

func EcdsaSignRound2Exec(sessionId string) *MpcResult {
	res := onsign.OnsignRound2Exec(sessionId)
	return toMpcRes(res)
}

func GetSignRound2Msg(sessionId string, toDeviceId string) *MpcExecResult {
	res := onsign.GetRound2Msg(sessionId, toDeviceId)
	return toMpcExecRes(res)
}

func EcdsaSignRound2MsgAccept(sessionId string, recv []byte) *MpcResult {
	res := onsign.OnSignRound2MsgAccept(sessionId, recv)
	return toMpcRes(res)
}

func EcdsaSignRound2Finish(sessionId string) *MpcResult {
	res := onsign.OnSignRound2Finish(sessionId)
	return toMpcRes(res)
}

func EcdsaSignRound3Exec(sessionId string) *MpcResult {
	res := onsign.OnsignRound3Exec(sessionId)
	return toMpcRes(res)
}

func GetSignRound3Msg(sessionId string, toDeviceId string) *MpcExecResult {
	res := onsign.GetRound3Msg(sessionId, toDeviceId)
	return toMpcExecRes(res)
}

func EcdsaSignRound3MsgAccept(sessionId string, recv []byte) *MpcResult {
	res := onsign.OnSignRound3MsgAccept(sessionId, recv)
	return toMpcRes(res)
}

func EcdsaSignRound3Finish(sessionId string) *MpcResult {
	res := onsign.OnSignRound3Finish(sessionId)
	return toMpcRes(res)
}

func EcdsaSignRound4Exec(sessionId string) *MpcExecResult {
	res := onsign.OnsignRound4Exec(sessionId)
	return toMpcExecRes(res)
}

func EcdsaSignRound4MsgAccept(sessionId string, recv []byte) *MpcResult {
	res := onsign.OnSignRound4MsgAccept(sessionId, recv)
	return toMpcRes(res)
}

func EcdsaSignRound4Finish(sessionId string) *MpcResult {
	res := onsign.OnSignRound4Finish(sessionId)
	return toMpcRes(res)
}

func EcdsaSignFinalExec(sessionId string) *MpcResult {
	res := onsign.OnsignRound3Exec(sessionId)
	return toMpcRes(res)
}
