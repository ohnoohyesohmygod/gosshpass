package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
)

// GetPWD get real password
func GetPWD(aesEncrypt *AesEncrypt, host, user string) (string, error) {
	cipherPWD, err := LoadCipherPWD(host, user)
	if err != nil {
		return "", err
	}

	clearText, err := aesEncrypt.Decrypt(cipherPWD)
	if err != nil {
		return "", err
	}
	return string(clearText), nil
}

// LoadCipherPWD load cipher password from ~/.ssh/gosshpass
func LoadCipherPWD(host, user string) ([]byte, error) {
	pwdfile, err := getPWDFilePath()
	if err != nil {
		return nil, err
	}

	file, err := os.Open(pwdfile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var h, u, p string
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}

		fmt.Sscanf(line, "%s %s %s", &h, &u, &p)
		if h == host && u == user {
			p = strings.TrimRight(p, "\n")
			pwdByte, err := base64.StdEncoding.DecodeString(p)
			if err != nil {
				return nil, err
			}
			return pwdByte, nil
		}
	}

	return nil, errors.New("not found host:" + host + " user:" + user)
}

// SavePWD save password
func SavePWD(aesEncrypt *AesEncrypt, host, user, pwd string) error {
	pwdfile, err := getPWDFilePath()
	if err != nil {
		return err
	}

	file, err := os.OpenFile(pwdfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	cipherByte, err := aesEncrypt.Encrypt([]byte(pwd))
	if err != nil {
		return err
	}

	base64PWD := base64.StdEncoding.EncodeToString(cipherByte)
	newLine := host + " " + user + " " + base64PWD + "\n"
	writer := bufio.NewWriter(file)
	writer.WriteString(newLine)
	writer.Flush()

	return nil
}

// GenAESEncrypt gen a AES encrypt
func GenAESEncrypt(aesKey, host, user string) *AesEncrypt {
	str := strings.Trim(aesKey+host+user, " ")
	key := []byte(str)
	len := len(str)
	if len < 16 {
		for i := 0; i < 16-len; i++ {
			key = append(key, byte(i))
		}
	}

	aesEncrypt := new(AesEncrypt)
	aesEncrypt.SetKey(key)

	return aesEncrypt
}

// getPWDFilePath gosshpass file path (~/.ssh/gosshpass)
func getPWDFilePath() (string, error) {
	u, err := user.Current()
	if nil == err {
		return u.HomeDir + "/.ssh/gosshpass", nil
	}

	if home := os.Getenv("HOME"); home != "" {
		return home + "/.ssh/gosshpass", nil
	}

	return "", errors.New("get gosshpass file path error")
}
