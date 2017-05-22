package main

import (
	"fmt"
	"testing"
)

func TestEncrypt(t *testing.T) {
	txt := "123456"

	// aesEncrypt := new(AesEncrypt)
	// err := aesEncrypt.SetKey([]byte("23asdv35df127.0."))
	// if err != nil {
	// 	t.Error("set key error", err)
	// }

	aesEncrypt := GenAESEncrypt("23asdv35df", "127.0.0.1", "root")

	fmt.Println("=======" + string(aesEncrypt.key) + "==========")

	cipherByte, err := aesEncrypt.Encrypt([]byte(txt))
	if err != nil {
		t.Error("encrypt error")
	}
	fmt.Println(string(cipherByte))

	clearByte, err := aesEncrypt.Decrypt(cipherByte)
	if err != nil {
		t.Error("decrypt error")
	}
	if string(clearByte) != txt {
		t.Error("decrypt error")
	}
}
