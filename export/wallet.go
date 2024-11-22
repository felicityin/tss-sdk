package tssdk

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"

	"tss-sdk/hwallet/bip39"
	"tss-sdk/hwallet/blocktree/go-owcdrivers/owkeychain"
	"tss-sdk/hwallet/blocktree/go-owcrypt"
	"tss-sdk/hwallet/hdwallet"
	"tss-sdk/tss/tss"
)

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

// pinCode: eg. 124561
func GenHardWalletPriv(mnemonic string, pinCode string) *WalletResult {
	seed, err := hdwallet.NewSeed(mnemonic, "", hdwallet.English)
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

func GetFingerPrint(mnemonic string) *WalletResult {
	status := bip39.IsMnemonicValid(mnemonic)
	result := &WalletResult{Success: status}
	if status {
		seed, err := hdwallet.NewSeed(mnemonic, "", hdwallet.English)
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

// 检验是否是相关币种地址
func CheckAddress(address, coin string) bool {
	return hdwallet.CheckCoinAddress(address, coin)
}

func GetChainType(chain string) int {
	return hdwallet.GetChainType(chain)
}

func GenerateAddress(pubkeyHex, coin string) string {
	return hdwallet.GenerateAddress(pubkeyHex, coin)
}

// 根据助词和路径生成钱包
func GeneratePathWallet(mn, path string) *WalletResult {
	seed, err := hdwallet.NewSeed(mn, "", hdwallet.English)
	if err != nil {
		return &WalletResult{Success: false, ErrMsg: err.Error()}
	}
	masterPriv, ch := hdwallet.ComputeMastersFromSeed(seed)

	derivedPriv, ch, err := hdwallet.DerivePrivateKeyForPath(masterPriv, ch, path)
	if err != nil {
		return &WalletResult{Success: false, ErrMsg: err.Error()}
	}

	return &WalletResult{
		Success:   true,
		ChainCode: hex.EncodeToString(ch[:]),
		Result:    hex.EncodeToString(derivedPriv[:]),
	}
}

func GetSignatureHash(data string) string {
	content, _ := hex.DecodeString(data)
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(content))
	message := append([]byte(msg), content...)
	return crypto.Keccak256Hash(message).Hex()

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
