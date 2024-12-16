package tssdk

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	keygen "tss-sdk/tss/protocols/cggmp/keygen/threshold"
)

func NewTKeygenLocalParty(
	algo string, // ecdsa or eddsa
	sessionId string,
	sessionKind string,
	deviceId string,
	allDevices string, // comma separated
	connIds string, // comma separated
	rootPrivKey string, // hex string
	chainCode string, // hex string
) *MpcResult {
	parties, connectIds, err := parseParties(allDevices, connIds)
	if err != nil {
		return &MpcResult{Ok: false, Err: err.Error()}
	}
	res := keygen.NewLocalParty(algo, sessionId, sessionKind, deviceId, parties, connectIds, rootPrivKey, chainCode)
	return toMpcRes(res)
}

func RemoveTKeygenParty(sessionId string) bool {
	return keygen.RemoveParty(sessionId)
}

func TKeygenRound1Exec(sessionId string) *MpcExecResult {
	res := keygen.KeygenRound1Exec(sessionId)
	return toMpcExecRes(res)
}

func TKeygenRound1Accept(sessionId string, recv []byte) *MpcResult {
	res := keygen.KeygenRound1Accept(sessionId, recv)
	return toMpcRes(res)
}

func TKeygenRound1Finish(sessionId string) *MpcResult {
	res := keygen.KeygenRound1Finish(sessionId)
	return toMpcRes(res)
}

func TKeygenRound2Exec(sessionId string) *MpcExecResult {
	res := keygen.KeygenRound2Exec(sessionId)
	return toMpcExecRes(res)
}

func GetTKeygenRound2Msg2(sessionId string, toDeviceId string) *MpcExecResult {
	res := keygen.GetRound2Msg2(sessionId, toDeviceId)
	return toMpcExecRes(res)
}

func TKeygenRound2Accept(sessionId string, recv []byte) *MpcResult {
	res := keygen.KeygenRound2Accept(sessionId, recv)
	return toMpcRes(res)
}

func TKeygenRound2Finish(sessionId string) *MpcResult {
	res := keygen.KeygenRound2Finish(sessionId)
	return toMpcRes(res)
}

func TKeygenRound3Exec(sessionId string) *MpcExecResult {
	res := keygen.KeygenRound3Exec(sessionId)
	return toMpcExecRes(res)
}

func TKeygenRound3Accept(sessionId string, recv []byte) *MpcResult {
	res := keygen.KeygenRound3Accept(sessionId, recv)
	return toMpcRes(res)
}

func TKeygenRound3Finish(sessionId string) *MpcResult {
	res := keygen.KeygenRound3Finish(sessionId)
	return toMpcRes(res)
}

func TKeygenRound4Exec(sessionId string) *MpcExecResult {
	res := keygen.KeygenRound4Exec(sessionId)
	return toMpcExecRes(res)
}
