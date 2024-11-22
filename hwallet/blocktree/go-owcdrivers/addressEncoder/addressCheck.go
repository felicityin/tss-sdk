package addressEncoder

import (
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

var (
	ErrorSymbolType = errors.New("Invalid symbol type!!!")
)

/*
@function:check the address valid or not
@paramter[in]address denotes the input address to be checked
@paramter[in]symbol denotes chain marking.
@paramter[out] the first return value is true or false. true: address valid, false:address not valid;
			   the second return value is nil or others. nil: operation success, others:operation fail.
notice:
*/
func CheckAddress(address string) error {
	netParams := &chaincfg.MainNetParams
	_, err := btcutil.DecodeAddress(address, netParams)
	return err
}
func AddressCheck(addr string, symbol string) (bool, error) {
	var err error
	if symbol == "USDT" {
		symbol = "BTC"
	}
	switch symbol {
	case "BTC":
		err = CheckAddress(addr)
		if err == nil {
			return true, err
		} else {
			return false, err
		}
	case "BCH":
		if addr[0] == '1' {
			_, err = AddressDecode(addr, BCH_mainnetAddressLegacy)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		//other type(TODO)
		if addr[0] == 'b' && addr[1] == 'i' && addr[2] == 't' && addr[3] == 'c' &&
			addr[4] == 'o' && addr[5] == 'i' && addr[6] == 'n' && addr[7] == 'c' &&
			addr[8] == 'a' && addr[9] == 's' && addr[10] == 'h' && addr[11] == ':' {
			_, err = AddressDecode(addr, BCH_mainnetAddressCash)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
	case "BSV":
		if addr[0] == '1' {
			_, err = AddressDecode(addr, BSV_mainnetAddressP2PKH)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
	case "ETH":
		if len(addr) < 16 {
			return false, ErrorInvalidHashLength
		}
		_, err = AddressDecode(addr, ETH_mainnetPublicAddress)
		if err == nil {
			return true, err
		} else {
			return false, err
		}
	case "DASH":
		if addr[0] == 'X' {
			_, err = AddressDecode(addr, DASH_mainnetAddressP2PKH)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
	case "DOGE":
		if addr[0] == 'D' {
			_, err = AddressDecode(addr, DOGE_singleSignAddressP2PKH)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}

	case "LTC":
		if addr[0] == 'L' {
			_, err = AddressDecode(addr, LTC_mainnetAddressP2PKH)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == '3' {
			_, err = AddressDecode(addr, LTC_mainnetAddressP2SH)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'M' {
			_, err = AddressDecode(addr, LTC_mainnetAddressP2SH2)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'l' && addr[1] == 't' && addr[2] == 'c' {
			_, err = AddressDecode(addr, LTC_mainnetAddressBech32V0)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'm' || addr[0] == 'n' {
			_, err = AddressDecode(addr, LTC_testnetAddressP2PKH)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == '2' {
			_, err = AddressDecode(addr, LTC_testnetAddressP2SH)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 't' && addr[1] == 'l' && addr[2] == 't' && addr[3] == 'c' {
			_, err = AddressDecode(addr, LTC_testnetAddressBech32V0)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}

		//other type(TODO)
	case "DCR":
		if addr[0] == 'D' && addr[1] == 's' {
			_, err = AddressDecode(addr, DCRD_mainnetAddressP2PKH)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'b' && addr[1] == 'g' {
			_, err = AddressDecode(addr, DCRD_mainnetAddressP2PK)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'D' && addr[1] == 'e' {
			_, err = AddressDecode(addr, DCRD_mainnetAddressPKHEdwards)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'D' && addr[1] == 'S' {
			_, err = AddressDecode(addr, DCRD_mainnetAddressPKHSchnorr)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'D' && addr[1] == 'c' {
			_, err = AddressDecode(addr, DCRD_mainnetAddressP2SH)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == '2' && addr[1] == '4' {
			_, err = AddressDecode(addr, DCRD_mainnetAddressPrivate)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'T' && addr[1] == 's' {
			_, err = AddressDecode(addr, DCRD_testnetAddressP2PKH)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == '2' && addr[1] == 'F' {
			_, err = AddressDecode(addr, DCRD_testnetAddressP2PK)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'T' && addr[1] == 'e' {
			_, err = AddressDecode(addr, DCRD_testnetAddressPKHEdwards)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'T' && addr[1] == 'S' {
			_, err = AddressDecode(addr, DCRD_testnetAddressP2PKHSchnorr)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'T' && addr[1] == 'c' {
			_, err = AddressDecode(addr, DCRD_testnetAddressP2SH)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == '2' && addr[1] == '5' {
			_, err = AddressDecode(addr, DCRD_testnetAddressPrivate)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'S' && addr[1] == 's' {
			_, err = AddressDecode(addr, DCRD_simnetAddressP2PKH)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == '2' && addr[1] == 'D' {
			_, err = AddressDecode(addr, DCRD_simnetAddressP2PK)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'S' && addr[1] == 'e' {
			_, err = AddressDecode(addr, DCRD_simnetAddressPKHEdwards)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'S' && addr[1] == 'S' {
			_, err = AddressDecode(addr, DCRD_simnetAddressPKHSchnorr)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}
		if addr[0] == 'S' && addr[1] == 'c' {
			_, err = AddressDecode(addr, DCRD_simnetAddressP2SH)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}

		//other type(TODO)
	case "TRX":
		if addr[0] == 'T' {
			_, err = AddressDecode(addr, TRON_mainnetAddress)
			if err == nil {
				return true, err
			} else {
				return false, err
			}
		}

	default:
		return false, nil
		//不支持的币种忽略检查
	}
	return false, ErrorSymbolType
}
