package main

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// AesEncrypt the AES encrypt to save key
type AesEncrypt struct {
	key []byte
}

// SetKey set aes key
func (me *AesEncrypt) SetKey(key []byte) error {
	keyLen := len(key)
	switch {
	case keyLen < 16:
		return errors.New("res key 长度不能小于16")
	case keyLen >= 32:
		me.key = key[:32]
	case keyLen >= 24:
		me.key = key[:24]
	default:
		me.key = key[:16]
	}

	return nil
}

// Encrypt aes encrypt the content
func (me *AesEncrypt) Encrypt(content []byte) ([]byte, error) {
	iv := me.key[:aes.BlockSize]
	encrypted := make([]byte, len(content))
	block, err := aes.NewCipher(me.key)
	if err != nil {
		return nil, err
	}

	aesEncrypter := cipher.NewCFBEncrypter(block, iv)
	aesEncrypter.XORKeyStream(encrypted, content)
	return encrypted, nil
}

// Decrypt aes decrypt the cipherText
func (me *AesEncrypt) Decrypt(cipherText []byte) (clearText []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = e.(error)
		}
	}()

	var iv = me.key[:aes.BlockSize]
	decrypted := make([]byte, len(cipherText))
	var block cipher.Block
	block, err = aes.NewCipher(me.key)
	if err != nil {
		return nil, err
	}
	aesDecrypter := cipher.NewCFBDecrypter(block, iv)
	aesDecrypter.XORKeyStream(decrypted, cipherText)
	return decrypted, nil
}
