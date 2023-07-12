package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"

	"gopkg.in/yaml.v3"
)

type Confidential struct {
	Label string `yaml:"label"`
	Value string `yaml:"value"`
}

type Configuration struct {
	Key           string         `yaml:"key"`
	Confidentials []Confidential `yaml:"confidentials"`
}

type Encryption struct {
	Key []byte
}

func main() {
	yamlFile, err := ioutil.ReadFile("confidentials.yaml")
	if err != nil {
		log.Fatalf("Failed to read YAML file: %v", err)
	}

	var config Configuration

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Failed to unmarshal YAML: %v", err)
	}

	var option int
	var aesType int
	fmt.Print("Choose option \n1 => use key from YAML\n2 => auto generate key\n\n")
	fmt.Print("choose your option : ")
	fmt.Scan(&option)

	if option == 1 {
		encryption := Encryption{Key: []byte(config.Key)}

		for _, confidential := range config.Confidentials {
			safeVal, err := encryption.EncryptMessage(confidential.Value)
			if err != nil {
				panic(err.Error())
			}

			fmt.Printf("Label: %s\nSafe Value: %s\n\n", confidential.Label, safeVal)
		}
	}

	if option == 2 {
		var keylength int
		fmt.Print("select AES algorithm \n1 => AES128\n2 => AES192\n3 => AES256\n\n")
		fmt.Print("choose your AES algorithm : ")
		fmt.Scan(&aesType)
		switch aesType {
		case 1:
			keylength = 16
			fmt.Println("select AES128")
		case 2:
			keylength = 24
			fmt.Println("select AES192")
		case 3:
			keylength = 32
			fmt.Println("select AES156")
		}
		key := generateRandomString(keylength)
		fmt.Printf("key : %s\n\n", key)

		encryption := Encryption{Key: []byte(key)}

		for _, confidential := range config.Confidentials {
			safeVal, err := encryption.EncryptMessage(confidential.Value)
			if err != nil {
				panic(err.Error())
			}

			fmt.Printf("Label: %s\nSafe Value: %s\n\n", confidential.Label, safeVal)
		}
	}
}

func generateRandomString(length int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return ""
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret)
}

func (e *Encryption) EncryptMessage(message string) (string, error) {
	byteMsg := []byte(message)
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}
