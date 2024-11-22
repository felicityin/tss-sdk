package hdwallet

import (
	"encoding/hex"
	"math/big"
	"strings"

	"tss-sdk/hwallet/blocktree/go-owcdrivers/addressEncoder"
	"tss-sdk/tss/crypto"
	"tss-sdk/tss/tss"
)

func GenerateAddress(pubkeyHex string, coin string) string {
	point := strings.Split(pubkeyHex, "|")
	if len(point) == 2 {
		pkX, _ := new(big.Int).SetString(point[0], 16)
		pkY, _ := new(big.Int).SetString(point[1], 16)
		point, err := crypto.NewECPoint(tss.S256(), pkX, pkY)
		if err != nil {
			return ""
		}
		pt, _ := point.MarshalJSON()
		pubkeyHex = hex.EncodeToString(pt)
	}

	coinType := strings.ToUpper(coin)
	if len(pubkeyHex) < 1 {
		return ""
	}
	pk, _ := hex.DecodeString(pubkeyHex)
	switch coinType {
	case "BTC":
		return addressEncoder.AddressEncode(pk, addressEncoder.BTC_mainnetAddressP2PKH)
	case "BCH":
		return addressEncoder.AddressEncode(pk, addressEncoder.BCH_mainnetAddressCash)
	case "LTC":
		return addressEncoder.AddressEncode(pk, addressEncoder.LTC_mainnetAddressP2PKH)
	case "TRX":
		return addressEncoder.AddressEncode(pk, addressEncoder.TRON_mainnetAddress)
	case "DOGE":
		return addressEncoder.AddressEncode(pk, addressEncoder.DOGE_singleSignAddressP2PKH)
	case "DASH":
		return addressEncoder.AddressEncode(pk, addressEncoder.DASH_mainnetAddressP2PKH)
	case "BNB_BSC":
		return "0x" + addressEncoder.AddressEncode(pk, addressEncoder.ETH_mainnetPublicAddress)
	case "ETH":
		return "0x" + addressEncoder.AddressEncode(pk, addressEncoder.ETH_mainnetPublicAddress)
	case "MATIC_POLYGON":
		return "0x" + addressEncoder.AddressEncode(pk, addressEncoder.ETH_mainnetPublicAddress)
	case "HT_HECO":
		return "0x" + addressEncoder.AddressEncode(pk, addressEncoder.ETH_mainnetPublicAddress)
	case "ETH_ARBITRUM":
		return "0x" + addressEncoder.AddressEncode(pk, addressEncoder.ETH_mainnetPublicAddress)
	case "ETH_OPTIMISM":
		return "0x" + addressEncoder.AddressEncode(pk, addressEncoder.ETH_mainnetPublicAddress)
	default:
		return ""
	}
}
func GetChainType(chain string) int {
	coinType := strings.ToUpper(chain)
	switch coinType {
	case "BTC":
		return 0
	case "BCH":
		return 145
	case "LTC":
		return 2
	case "TRX":
		return 195
	case "DOGE":
		return 3
	case "DASH":
		return 5
	case "BNB_BSC":
		return 60
	case "ETH":
		return 60
	case "MATIC_POLYGON":
		return 60
	case "HT_HECO":
		return 60
	case "ETH_ARBITRUM":
		return 60
	case "ETH_OPTIMISM":
		return 60
	case "DOT":
		return 354
	case "SOL":
		return 501
	case "APT":
		return 637
	case "ETH_BASE":
		return 60
	default:
		return -1
	}
}
func CheckCoinAddress(address string, coin string) bool {
	coinType := strings.ToUpper(coin)
	if len(address) < 1 {
		return false
	}
	switch coinType {

	case "BCH":
		if address[0] != '1' {
			if address[0] != 'b' {
				address = "bitcoincash:" + address
			}
		}
		result, err := addressEncoder.AddressCheck(address, coinType)
		if err != nil {
			return false
		}
		return result
	case "BSC":
		result, err := addressEncoder.AddressCheck(address, "ETH")
		if err != nil {
			return false
		}
		return result
	case "FANTOM":
		result, err := addressEncoder.AddressCheck(address, "ETH")
		if err != nil {
			return false
		}
		return result
	case "POLYGON":
		result, err := addressEncoder.AddressCheck(address, "ETH")
		if err != nil {
			return false
		}
		return result
	case "ZKSYNC":
		result, err := addressEncoder.AddressCheck(address, "ETH")
		if err != nil {
			return false
		}
		return result
	case "HT_HECO":
		result, err := addressEncoder.AddressCheck(address, "ETH")
		if err != nil {
			return false
		}
		return result
	case "ARBITRUM":
		result, err := addressEncoder.AddressCheck(address, "ETH")
		if err != nil {
			return false
		}
		return result
	case "OPTIMISM":
		result, err := addressEncoder.AddressCheck(address, "ETH")
		if err != nil {
			return false
		}
		return result
	case "AVAX-C":
		result, err := addressEncoder.AddressCheck(address, "ETH")
		if err != nil {
			return false
		}
		return result
	case "HSC":
		result, err := addressEncoder.AddressCheck(address, "ETH")
		if err != nil {
			return false
		}
		return result
	default:
		result, err := addressEncoder.AddressCheck(address, coinType)
		if err != nil {
			return false
		}
		return result
	}

}
