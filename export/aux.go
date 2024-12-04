package tssdk

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	aux "tss-sdk/tss/protocols/cggmp/auxiliary"
)

func NewAuxLocalParty(
	sessionId string,
	sessionKind string,
	deviceId string,
	partyDevices string, // comma separated
	connIds string, // comma separated
) *MpcResult {
	parties, connectIds, err := parseParties(partyDevices, connIds)
	if err != nil {
		return &MpcResult{Ok: false, Err: err.Error()}
	}
	res := aux.NewLocalParty(sessionId, sessionKind, deviceId, parties, connectIds)
	return toMpcRes(res)
}

func RemoveAuxParty(sessionId string) bool {
	return aux.RemoveAuxParty(sessionId)
}

func AuxRound1Exec(sessionId string) *MpcExecResult {
	res := aux.AuxRound1Exec(sessionId)
	return toMpcExecRes(res)
}

func AuxRound1Accept(sessionId string, recv []byte) *MpcResult {
	res := aux.AuxRound1Accept(sessionId, recv)
	return toMpcRes(res)
}

func AuxRound1Finish(sessionId string) *MpcResult {
	res := aux.AuxRound1Finish(sessionId)
	return toMpcRes(res)
}

func AuxRound2Exec(sessionId string) *MpcExecResult {
	res := aux.AuxRound2Exec(sessionId)
	return toMpcExecRes(res)
}

func AuxRound2Accept(sessionId string, recv []byte) *MpcResult {
	res := aux.AuxRound2Accept(sessionId, recv)
	return toMpcRes(res)
}

func AuxRound2Finish(sessionId string) *MpcResult {
	res := aux.AuxRound2Finish(sessionId)
	return toMpcRes(res)
}

func AuxRound3Exec(sessionId string) *MpcResult {
	res := aux.AuxRound3Exec(sessionId)
	return toMpcRes(res)
}

func GetAuxRound3Msg(sessionId string, toDeviceId string) *MpcExecResult {
	res := aux.GetRound3Msg(sessionId, toDeviceId)
	return toMpcExecRes(res)
}

func AuxRound3Accept(sessionId string, recv []byte) *MpcResult {
	res := aux.AuxRound3Accept(sessionId, recv)
	return toMpcRes(res)
}

func AuxRound3Finish(sessionId string) *MpcResult {
	res := aux.AuxRound3Finish(sessionId)
	return toMpcRes(res)
}

func AuxRound4Exec(sessionId string) *MpcExecResult {
	res := aux.AuxRound4Exec(sessionId)
	return toMpcExecRes(res)
}
