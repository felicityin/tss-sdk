package hdwallet

var coins = make(map[uint32]func(*Key) Wallet)

// Wallet interface
type Wallet interface {
	GetType() uint32
	GetName() string
	GetKey() *Key
	SignRawTransaction(signIn *SignInput) (*SignResult, error)
}

type WalletAccount struct {
	Res        int    // 0 失败 1 成功
	Address    string // 成功必定包含地址
	PublicKey  string // 公钥
	PrivateKey string // 私钥
	Seed       string //根Seed
	Coin       string //币种
	ErrMsg     string // 失败原因(便于排查问题,不是必定返回)
	ErrCode    int    //错误码
	Params     string //预留字段
}
type SignInput struct {
	Seed         string `json:"seed"`
	Path         string `json:"path"`
	Coin         string `json:"coin"`
	Amount       string `json:"amount"`
	SrcAddr      string `json:"srcAddr"`
	DestAddr     string `json:"destAddr"`
	ContractAddr string `json:"contractAddr"` //合约地址
	Decimal      int    `json:"decimal"`
	Nonce        int64  `json:"nonce"`    // eth etc nonce
	ChainID      int    `json:"chainID"`  // 网络
	Utxos        []byte `json:"utxos"`    // utxo构造
	GasLimit     int64  `json:"gasLimit"` // gas数量
	GasPrice     int64  `json:"gasPrice"` // gas价格
}

type SignResult struct {
	ResCode int    `json:"resCode"` // 0 失败 1 成功
	Coin    string `json:"coin"`    // 主链币
	RawTX   string `json:"rawTX"`   //签名后的数据
	ErrMsg  string `json:"errMsg"`  // 失败原因(便于排查问题,不是必定返回)
}
