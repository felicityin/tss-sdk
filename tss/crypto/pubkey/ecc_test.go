package pubkey

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEcc(t *testing.T) {
	pkStr := "026a396a23c195eef9a55d7fef4882a00e159ed30c84a7eda78b71a19f5b8b0616"
	pk, err := DecodeEcdsaPk(pkStr)
	assert.NoError(t, err)
	pkStr1, err := EncodeEcdsaPk(pk.X(), pk.Y())
	assert.NoError(t, err)
	assert.Equal(t, pkStr, pkStr1)

	pkStr = "3b8a74f609415a2b6a5ad8354c2a53aa971e2b0ca8743bb8147702e8cdf06315"
	pk1, err := DecodeEddsaPk(pkStr)
	assert.NoError(t, err)
	pkStr1 = EncodeEddsaPk(pk1.X, pk1.Y)
	assert.Equal(t, pkStr, pkStr1)
}
