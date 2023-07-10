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
	// Read the YAML file
	yamlFile, err := ioutil.ReadFile("confidentials.yaml")
	if err != nil {
		log.Fatalf("Failed to read YAML file: %v", err)
	}

	var config Configuration

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Failed to unmarshal YAML: %v", err)
	}

	encryption := Encryption{Key: []byte(config.Key)}

	for _, confidential := range config.Confidentials {
		safeVal, err := encryption.EncryptMessage(confidential.Value)
		if err != nil {
			panic(err.Error())
		}

		fmt.Printf("Label: %s\nSafe Value: %s\n\n", confidential.Label, safeVal)
	}
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
