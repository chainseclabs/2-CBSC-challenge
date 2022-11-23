package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
	"os"
)

type PemKeyChaincode struct {
}

type PemKey struct {
	PrivateKey string
	PublicKey  string
}

//init function
func (t *PemKeyChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {

	return shim.Success(nil)
}

func (t *PemKeyChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()

	if function == "GenerateKey" {

		key := args[0]
		state, err := stub.GetState(key)
		if err != nil {
			return shim.Error(err.Error())
		}

		if state != nil {
			return shim.Success(state)
		}

		//Generate Private Key
		privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			fmt.Println(err)
		}

		baseDir := "/tmp"
		privateKeyFileDir := baseDir + key + "_private.pem"

		//Generate Private Key
		privateKeyFile, err := os.Create(privateKeyFileDir)
		if err != nil {
			return shim.Error(err.Error())
		}

		//Save Private Key
		X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}

		//Save data to privateKeyFile
		err = pem.Encode(privateKeyFile, &privateKeyBlock)
		if err != nil {
			fmt.Println(err.Error())
			return shim.Error(err.Error())
		}

		err = os.Chmod(privateKeyFileDir, 0777)
		if err != nil {
			fmt.Println("Error when changing file permissions!")
			return shim.Error(err.Error())
		}

		//Get publicKey
		publicKey := privateKey.PublicKey
		//use X509 encoding
		X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
		if err != nil {
			fmt.Println(err)
		}
		publicKeyFileDir := baseDir + key + "_public.pem"

		//Generate Public Key File
		publicKeyFile, err := os.Create(publicKeyFileDir)
		if err != nil {
			return shim.Error(err.Error())
		}

		publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}
		err = pem.Encode(publicKeyFile, &publicBlock)
		if err != nil {
			return shim.Error(err.Error())
		}

		err = os.Chmod(publicKeyFileDir, 0777)
		if err != nil {
			fmt.Println("Error when changing file permissions!")
			return shim.Error(err.Error())
		}

		privateKeyContent, err := os.ReadFile(privateKeyFileDir)
		if err != nil {
			panic(err)
		}

		publicKeyContent, err := os.ReadFile(publicKeyFileDir)
		if err != nil {
			panic(err)
		}

		pemKey := PemKey{
			PrivateKey: string(privateKeyContent),
			PublicKey:  string(publicKeyContent),
		}

		bytes, err := json.Marshal(pemKey)

		err = stub.PutState(key, bytes)
		if err != nil {
			return shim.Error(err.Error())
		}

		err = os.Remove(privateKeyFileDir)

		err = os.Remove(publicKeyFileDir)

		return shim.Success(bytes)
	} else if function == "queryKey" {

		key := args[0]

		state, err := stub.GetState(key)
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success(state)
	}
	return shim.Error("")
}

func main() {
	err := shim.Start(new(PemKeyChaincode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode1: %s", err)
	}
}
