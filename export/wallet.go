package tssdk

import (
	"encoding/hex"
	"encoding/json"
	"math/big"

	"tss-sdk/hwallet/bip39"
	"tss-sdk/hwallet/blocktree/go-owcdrivers/owkeychain"
	"tss-sdk/hwallet/blocktree/go-owcrypt"
	"tss-sdk/hwallet/hdwallet"
	"tss-sdk/tss/tss"
)

const CipherSafe = "CipherSafe"

type WalletResult struct {
	Result    string `json:"result"`
	ChainCode string `json:"chaincode"`
	Success   bool   `json:"success"` // 统一字段, 是否执行成功
	ErrMsg    string `json:"errMsg"`  // 失败原因(便于排查问题,不是必定返回)
}

func (wallet WalletResult) ToJson() string {
	b, _ := json.Marshal(wallet)
	return string(b)
}

func GenerateMnemonic(length int) string {
	mn, err := hdwallet.NewMnemonic(length, hdwallet.English)
	if err != nil {
		return ""
	}
	return mn
}

func MnemonicToSeed(mnemonic string) *WalletResult {
	seed, err := hdwallet.NewSeed(mnemonic, CipherSafe, hdwallet.English)
	if err != nil {
		return &WalletResult{Success: false, ErrMsg: err.Error()}
	}
	return &WalletResult{Success: true, Result: hex.EncodeToString(seed)}
}

// pinCode: is a 6-digit number. eg. 124561
func GenHardWalletPriv(mnemonic string, pinCode string) *WalletResult {
	seed, err := hdwallet.NewSeed(mnemonic, CipherSafe, hdwallet.English)
	if err != nil {
		return &WalletResult{Success: false, ErrMsg: err.Error()}
	}

	masterPriv, chainCode := hdwallet.ComputeMasterFromSeed(seed, pinCode)

	return &WalletResult{
		Success:   true,
		ChainCode: hex.EncodeToString(chainCode[:]),
		Result:    hex.EncodeToString(masterPriv[:]),
	}
}

// pinCode: is a 6-digit number. eg. 124561
func GenHardWalletPrivBySeed(seed string, pinCode string) *WalletResult {
	decodedSeed, err := hex.DecodeString(seed)
	if err != nil {
		return &WalletResult{Success: false, ErrMsg: err.Error()}
	}

	masterPriv, chainCode := hdwallet.ComputeMasterFromSeed(decodedSeed, pinCode)

	return &WalletResult{
		Success:   true,
		ChainCode: hex.EncodeToString(chainCode[:]),
		Result:    hex.EncodeToString(masterPriv[:]),
	}
}

func GenHardWalletFingerPrint(mnemonic, pinCode string) *WalletResult {
	status := bip39.IsMnemonicValid(mnemonic)
	result := &WalletResult{Success: status}
	if status {
		seed, err := hdwallet.NewSeed(mnemonic, CipherSafe, hdwallet.English)
		if err != nil {
			return &WalletResult{Success: false, ErrMsg: err.Error()}
		}
		masterPriv, _ := hdwallet.ComputeMasterFromSeed(seed, pinCode)
		finger := owkeychain.GetFingerPrint(masterPriv[:], true, owcrypt.ECC_CURVE_SECP256K1)
		result.Result = hex.EncodeToString(finger)
	} else {
		result.ErrMsg = "Vaild mnemonic not passed!"
	}
	return result
}

func GenHardWalletFingerPrintBySeed(seed, pinCode string) *WalletResult {
	decodedSeed, err := hex.DecodeString(seed)
	if err != nil {
		return &WalletResult{Success: false, ErrMsg: err.Error()}
	}

	masterPriv, _ := hdwallet.ComputeMasterFromSeed(decodedSeed, pinCode)
	finger := owkeychain.GetFingerPrint(masterPriv[:], true, owcrypt.ECC_CURVE_SECP256K1)
	return &WalletResult{Success: true, Result: hex.EncodeToString(finger)}
}

func GenFingerPrint(mnemonic string) *WalletResult {
	status := bip39.IsMnemonicValid(mnemonic)
	result := &WalletResult{Success: status}
	if status {
		seed, err := hdwallet.NewSeed(mnemonic, CipherSafe, hdwallet.English)
		if err != nil {
			return &WalletResult{Success: false, ErrMsg: err.Error()}
		}
		masterPriv, _ := hdwallet.ComputeMastersFromSeed(seed)
		finger := owkeychain.GetFingerPrint(masterPriv[:], true, owcrypt.ECC_CURVE_SECP256K1)
		result.Result = hex.EncodeToString(finger)
	} else {
		result.ErrMsg = "Vaild mnemonic not passed!"
	}
	return result
}

func VaildMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(mnemonic)
}

func GetSignature(rx, ry, s string) string {
	Rx, _ := new(big.Int).SetString(rx, 10)
	S, _ := new(big.Int).SetString(s, 10)
	Ry, _ := new(big.Int).SetString(ry, 10)

	V := getSignatureRecoveryV(Rx, Ry, S)

	bytes := make([]byte, 0)
	bytes = append(bytes, Rx.Bytes()...)
	bytes = append(bytes, S.Bytes()...)
	bytes = append(bytes, V)
	return hex.EncodeToString(bytes)
}

func GetSignatureWithV(rx, ry, s string, v uint8) string {
	Rx, _ := new(big.Int).SetString(rx, 10)
	S, _ := new(big.Int).SetString(s, 10)
	Ry, _ := new(big.Int).SetString(ry, 10)

	V := getSignatureRecoveryV(Rx, Ry, S)

	bytes := make([]byte, 0)
	bytes = append(bytes, Rx.Bytes()...)
	bytes = append(bytes, S.Bytes()...)
	bytes = append(bytes, V)
	bytes[64] += v
	return hex.EncodeToString(bytes)
}

func getSignatureRecoveryV(rx *big.Int, ry *big.Int, s *big.Int) byte {
	recid := 0
	if rx.Cmp(tss.S256().Params().N) > 0 {
		recid = 2
	}
	if ry.Bit(0) != 0 {
		recid |= 1
	}
	secp256k1halfN := new(big.Int).Rsh(tss.S256().Params().N, 1)
	if s.Cmp(secp256k1halfN) > 0 {
		s.Sub(tss.S256().Params().N, s)
		recid ^= 1
	}
	return byte(recid)
}
