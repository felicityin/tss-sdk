package tssdk

import (
	onsign "tss-sdk/tss/protocols/frost/sign"
)

func NewEddsaSignLocalParty(
	isThreshold bool,
	sessionId string,
	sessionKind string,
	deviceId string,
	allDevices string, // comma separated
	connIds string, // comma separated
	msg string, // hex string
	keyData string, // keygen.LocalPartySaveData, base64 string
	walletPath string,
) *MpcResult {
	parties, connectIds, err := parseParties(allDevices, connIds)
	if err != nil {
		return &MpcResult{Ok: false, Err: err.Error()}
	}
	res := onsign.NewLocalParty(isThreshold, sessionId, sessionKind, deviceId, parties, connectIds, msg, keyData, walletPath)
	return toMpcRes(res)
}

func RemoveEddsaSignParty(sessionId string) bool {
	return onsign.RemoveSignParty(sessionId)
}

func EddsaSignRound1Exec(sessionId string) *MpcExecResult {
	res := onsign.OnSignRound1Exec(sessionId)
	return toMpcExecRes(res)
}

func EddsaSignRound1MsgAccept(sessionId string, recv []byte) *MpcResult {
	res := onsign.OnSignRound1MsgAccept(sessionId, recv)
	return toMpcRes(res)
}

func EddsaSignRound1Finish(sessionId string) *MpcResult {
	res := onsign.OnSignRound1Finish(sessionId)
	return toMpcRes(res)
}

func EddsaSignRound2Exec(sessionId string) *MpcExecResult {
	res := onsign.OnsignRound2Exec(sessionId)
	return toMpcExecRes(res)
}

func EddsaSignRound2MsgAccept(sessionId string, recv []byte) *MpcResult {
	res := onsign.OnSignRound2MsgAccept(sessionId, recv)
	return toMpcRes(res)
}

func EddsaSignRound2Finish(sessionId string) *MpcResult {
	res := onsign.OnSignRound2Finish(sessionId)
	return toMpcRes(res)
}

func EddsaSignFinalExec(sessionId string) *MpcExecResult {
	res := onsign.OnsignRound3Exec(sessionId)
	return toMpcExecRes(res)
}
