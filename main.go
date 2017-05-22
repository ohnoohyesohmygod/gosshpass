package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
)

var host = flag.String("h", "localhost", "remote server host")
var loginUser = flag.String("u", "root", "login user")
var isSavePWD = flag.Bool("s", false, "is save password [true|false]")

func main() {
	flag.Parse()

	if *isSavePWD {
		err := save()
		if err != nil {
			log.Fatal(err)
			return
		}
	} else {
		err := runSSHPass(*host, *loginUser)
		if err != nil {
			log.Fatal(err)
			return
		}
	}
}

func save() error {
	var h, u, p, pwdBookPWD string
	fmt.Println("please input host:")
	fmt.Scanln(&h)
	fmt.Println("please input login user:")
	fmt.Scanln(&u)
	fmt.Println("please input login password:")
	fmt.Scanln(&p)
	fmt.Println("please input ciphers file password(for encrypt login password):")
	fmt.Scanln(&pwdBookPWD)

	aesEncrypt := GenAESEncrypt(pwdBookPWD, h, u)
	return SavePWD(aesEncrypt, h, u, p)
}

func runSSHPass(host, user string) error {
	fmt.Println("please input password book pwd:")

	var aesKey string
	fmt.Scanln(&aesKey)

	aesEncrypt := GenAESEncrypt(aesKey, host, user)
	pwd, err := GetPWD(aesEncrypt, host, user)
	if err != nil {
		log.Fatal("load pwd error", err)
		return err
	}

	cmd := exec.Command("/bin/sh", "-c", "/usr/local/bin/sshpass -p '"+pwd+"' ssh "+user+"@"+host+" -tt")
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Start()
	cmd.Run()
	cmd.Wait()

	return nil
}
