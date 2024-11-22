package tssdk

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"

	"github.com/DataDog/zstd"
	"golang.org/x/crypto/scrypt"
)

type RSResult struct {
	ResultBytes string `json:"resultBytes"`
	Success     bool   `json:"success"` // 统一字段, 是否执行成功
	ErrMsg      string `json:"errMsg"`  // 如果 Success=false, 会返回失败原因 (便于排查问题,不是必定返回)
}

func (result RSResult) ToJson() string {
	b, _ := json.Marshal(result)
	return string(b)
}

func Encrypt(plainText, password string) *RSResult {
	boolResult := true
	var errStr string
	encrytedBytes, err := encrypt([]byte(password), []byte(plainText))
	if err != nil {
		boolResult = false
		errStr = err.Error()
	}
	return &RSResult{
		ResultBytes: hex.EncodeToString(encrytedBytes),
		Success:     boolResult,
		ErrMsg:      errStr,
	}
}

func EncryptHexStr(plainHexText, password string) *RSResult {
	boolResult := true
	var errStr string
	plainHexBytes, err := hex.DecodeString(plainHexText)
	if err != nil {
		boolResult = false
		errStr = err.Error()
		return &RSResult{
			ResultBytes: "",
			Success:     boolResult,
			ErrMsg:      errStr,
		}
	}
	encrytedBytes, err := encrypt([]byte(password), plainHexBytes)
	if err != nil {
		boolResult = false
		errStr = err.Error()
	}
	return &RSResult{
		ResultBytes: hex.EncodeToString(encrytedBytes),
		Success:     boolResult,
		ErrMsg:      errStr,
	}
}

func Decrypt(encryptedText, password string) *RSResult {
	boolResult := true
	var errStr string
	encryptedBytes, err := hex.DecodeString(encryptedText)
	if err != nil {
		boolResult = false
		errStr = err.Error()
		return &RSResult{
			ResultBytes: "",
			Success:     boolResult,
			ErrMsg:      errStr,
		}
	}
	var resStr string
	plainBytes, err := decrypt([]byte(password), encryptedBytes)
	if err != nil {
		boolResult = false
		errStr = err.Error()
	} else {
		resStr = string(plainBytes)
	}
	return &RSResult{
		ResultBytes: resStr,
		Success:     boolResult,
		ErrMsg:      errStr,
	}
}

func Compress(plainHexText string) *RSResult {
	boolResult := true
	var errStr string
	var resStr string
	plainHexBytes, err := hex.DecodeString(plainHexText)
	if err != nil {
		boolResult = false
		errStr = err.Error()
		return &RSResult{
			ResultBytes: "",
			Success:     boolResult,
			ErrMsg:      errStr,
		}
	}
	compressedBytes, err := zstdCompress(plainHexBytes)
	if err != nil {
		boolResult = false
		errStr = err.Error()
	} else {
		resStr = hex.EncodeToString(compressedBytes)
	}
	return &RSResult{
		ResultBytes: resStr,
		Success:     boolResult,
		ErrMsg:      errStr,
	}
}

func Decompress(compressedText string) *RSResult {
	boolResult := true
	var errStr string
	compressedBytes, err := hex.DecodeString(compressedText)
	if err != nil {
		boolResult = false
		errStr = err.Error()
		return &RSResult{
			ResultBytes: "",
			Success:     boolResult,
			ErrMsg:      errStr,
		}
	}
	var resStr string
	plainBytes, err := zstdUnCompress(compressedBytes)
	if err != nil {
		boolResult = false
		errStr = err.Error()
	} else {
		resStr = hex.EncodeToString(plainBytes)
	}
	return &RSResult{
		ResultBytes: resStr,
		Success:     boolResult,
		ErrMsg:      errStr,
	}
}

func encrypt(key, data []byte) ([]byte, error) {
	key, salt, err := deriveKey(key, nil)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	ciphertext = append(ciphertext, salt...)

	return ciphertext, nil
}

func decrypt(key, data []byte) ([]byte, error) {
	salt, data := data[len(data)-32:], data[:len(data)-32]

	key, _, err := deriveKey(key, salt)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	key, err := scrypt.Key(password, salt, 128, 2, 1, 32)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

func zstdCompress(src []byte) ([]byte, error) {
	return zstd.CompressLevel(nil, src, 19)
}

func zstdUnCompress(compressSrc []byte) ([]byte, error) {
	data, err := zstd.Decompress(nil, compressSrc)
	return data, err
}
