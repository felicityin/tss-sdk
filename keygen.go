package tsssdk

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"encoding/json"
	"strings"

	keygen "tss-sdk/tss/protocols/cggmp/keygen/non_threshold"
)

type MpcExecResult struct {
	Ok           bool   `json:"ok"`
	Err          string `json:"error"`
	MsgWireBytes []byte `json:"data"`
}

type MpcResult struct {
	Ok  bool   `json:"ok"`
	Err string `json:"error"`
}

func (result MpcExecResult) ToJson() string {
	b, _ := json.Marshal(result)
	return string(b)
}

func (result MpcResult) ToJson() string {
	b, _ := json.Marshal(result)
	return string(b)
}

func NewKeygenLocalParty(
	key string,
	partyIndex int,
	partyCount int,
	pIDs string,
	rootPrivKey string, // hex string
	chainCode string, // hex string
) *MpcResult {
	ids := strings.Split(pIDs, ",")
	res := keygen.NewLocalParty(key, partyIndex, partyCount, ids, rootPrivKey, chainCode)
	return resFromKeygen(res)
}

func RemoveKeygenParty(key string) bool {
	return keygen.RemoveParty(key)
}

func KeygenRound1Exec(key string) *MpcExecResult {
	res := keygen.KeygenRound1Exec(key)
	return execResFromKeygen(res)
}

func KeygenRound1Accept(key string, from int, msgWireBytes string) *MpcResult {
	res := keygen.KeygenRound1Accept(key, from, msgWireBytes)
	return resFromKeygen(res)
}

func KeygenRound1Finish(key string) *MpcResult {
	res := keygen.KeygenRound1Finish(key)
	return resFromKeygen(res)
}

func KeygenRound2Exec(key string) *MpcExecResult {
	res := keygen.KeygenRound2Exec(key)
	return execResFromKeygen(res)
}

func KeygenRound2Accept(key string, from int, msgWireBytes string) *MpcResult {
	res := keygen.KeygenRound2Accept(key, from, msgWireBytes)
	return resFromKeygen(res)
}

func KeygenRound2Finish(key string) *MpcResult {
	res := keygen.KeygenRound2Finish(key)
	return resFromKeygen(res)
}

func KeygenRound3Exec(key string) *MpcExecResult {
	res := keygen.KeygenRound3Exec(key)
	return execResFromKeygen(res)
}

func KeygenRound3Accept(key string, from int, msgWireBytes string) *MpcResult {
	res := keygen.KeygenRound3Accept(key, from, msgWireBytes)
	return resFromKeygen(res)
}

func KeygenRound3Finish(key string) *MpcResult {
	res := keygen.KeygenRound3Finish(key)
	return resFromKeygen(res)
}

// chainCodes: hex string array
func KeygenRound4Exec(key string) *MpcExecResult {
	res := keygen.KeygenRound4Exec(key)
	return execResFromKeygen(res)
}

func execResFromKeygen(res keygen.KeygenExecResult) *MpcExecResult {
	return &MpcExecResult{
		Ok:           res.Ok,
		Err:          res.Err,
		MsgWireBytes: res.MsgWireBytes,
	}
}

func resFromKeygen(res keygen.KeygenResult) *MpcResult {
	return &MpcResult{
		Ok:  res.Ok,
		Err: res.Err,
	}
}
