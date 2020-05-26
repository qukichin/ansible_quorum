package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	privateKey := RandPk()
	fmt.Println(privateKey)
	publicKey := Pk2Pub(privateKey)
	fmt.Println(publicKey)
}

// 1. 随机生成十六进制私钥字符串
func RandPk() string {
	priKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return fmt.Sprintf("0x%x", priKey.D)
}

// Encode encodes b as a hex string with 0x prefix.
func encode(b []byte) string {
	enc := make([]byte, len(b)*2)
	hex.Encode(enc, b)
	return string(enc)
}

func has0xPrefix(input string) bool {
	return len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')
}

// 2. 由十六进制私钥字符串导出十六进制公钥字符串
func Pk2Pub(pk string) string {
	if has0xPrefix(pk) {
		pk = pk[2:]
	}
	privateKey, err := crypto.HexToECDSA(pk)
	if err != nil {
		return ""
	}
	publicKey := elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y)
	return encode(publicKey)
}
