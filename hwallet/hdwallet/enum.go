package hdwallet

// mnemonic language
const (
	English            = "english"
	ChineseSimplified  = "chinese_simplified"
	ChineseTraditional = "chinese_traditional"
	Korean             = "korean"
)

// zero is deafult of uint32
const (
	Zero      uint32 = 0
	ZeroQuote uint32 = 0x80000000
	BTCToken  uint32 = 0x10000000
	ETHToken  uint32 = 0x20000000
)

// wallet type from bip44
const (
	// https://github.com/satoshilabs/slips/blob/master/slip-0044.md#registered-coin-types
	BTC       = ZeroQuote + 0
	LTC       = ZeroQuote + 2
	DOGE      = ZeroQuote + 3
	DASH      = ZeroQuote + 5
	Optimism  = ZeroQuote + 10
	ETH       = ZeroQuote + 60
	BCH       = ZeroQuote + 145
	TRX       = ZeroQuote + 195
	BSV       = ZeroQuote + 236
	Fantom    = ZeroQuote + 250
	ZKSYNC    = ZeroQuote + 324
	POLYGON   = ZeroQuote + 966
	ARBITRUM  = ZeroQuote + 42161
	OKChain   = ZeroQuote + 996
	BSC       = ZeroQuote + 714
	HECO      = ZeroQuote + 553
	Avalanche = ZeroQuote + 43114
)
