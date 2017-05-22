package main

import (
	"fmt"
	"testing"
)

const (
	testPassword  = "23asdv35df"
	testHost      = "127.0.0.1"
	testLoginUser = "root"
)

func TestGetPWD(t *testing.T) {
	aesEncrypt := GenAESEncrypt(testPassword, testHost, testLoginUser)
	fmt.Println("=======" + string(aesEncrypt.key) + "==========")
	pwd, err := GetPWD(aesEncrypt, testHost, testLoginUser)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(pwd)
}

func TestSavePWD(t *testing.T) {
	aesEncrypt := GenAESEncrypt(testPassword, testHost, testLoginUser)
	err := SavePWD(aesEncrypt, testHost, testLoginUser, "123456")
	if err != nil {
		t.Error(err)
	}
}

func TestGenAESEncrypt(t *testing.T) {
	aesEncrypt := GenAESEncrypt(testPassword, testHost, testLoginUser)
	fmt.Println(string(aesEncrypt.key))
}
