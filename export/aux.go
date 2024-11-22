package tssdk

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"strings"

	aux "tss-sdk/tss/protocols/cggmp/auxiliary"
)

func NewAuxLocalParty(
	key string,
	partyIndex int,
	partyCount int,
	pIDs string,
) *MpcResult {
	ids := strings.Split(pIDs, ",")
	res := aux.NewLocalParty(key, partyIndex, partyCount, ids)
	return toMpcRes(res)
}

func RemoveAuxParty(key string) bool {
	return aux.RemoveAuxParty(key)
}

func AuxRound1Exec(key string) *MpcExecResult {
	res := aux.AuxRound1Exec(key)
	return toMpcExecRes(res)
}

func AuxRound1Accept(key string, from int, msgWireBytes string) *MpcResult {
	res := aux.AuxRound1Accept(key, from, msgWireBytes)
	return toMpcRes(res)
}

func AuxRound1Finish(key string) *MpcResult {
	res := aux.AuxRound1Finish(key)
	return toMpcRes(res)
}

func AuxRound2Exec(key string) *MpcExecResult {
	res := aux.AuxRound2Exec(key)
	return toMpcExecRes(res)
}

func AuxRound2Accept(key string, from int, msgWireBytes string) *MpcResult {
	res := aux.AuxRound2Accept(key, from, msgWireBytes)
	return toMpcRes(res)
}

func AuxRound2Finish(key string) *MpcResult {
	res := aux.AuxRound2Finish(key)
	return toMpcRes(res)
}

func AuxRound3Exec(key string) *MpcResult {
	res := aux.AuxRound3Exec(key)
	return toMpcRes(res)
}

func GetAuxRound3Msg(key string, to int) *MpcExecResult {
	res := aux.GetRound3Msg(key, to)
	return toMpcExecRes(res)
}

func AuxRound3Accept(key string, from int, msgWireBytes string) *MpcResult {
	res := aux.AuxRound3Accept(key, from, msgWireBytes)
	return toMpcRes(res)
}

func AuxRound3Finish(key string) *MpcResult {
	res := aux.AuxRound3Finish(key)
	return toMpcRes(res)
}

// chainCodes: hex string array
func AuxRound4Exec(key string) *MpcExecResult {
	res := aux.AuxRound4Exec(key)
	return toMpcExecRes(res)
}
