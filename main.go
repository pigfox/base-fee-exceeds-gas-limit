package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/jimlawless/whereami"
	"golang.org/x/crypto/sha3"
)

var wallet map[string]string

var infura Infura
var connection string
var ipfsURL string

type Infura struct {
	ID  string
	URL string
}

func main() {
	fmt.Println(wallet)
	rawTx := createRawTransaction(wallet)
	sendRawTransaction(rawTx)
}

func init() {
	localHost := "http://127.0.0.1:7545" //requires Ganache to be running
	connection = localHost
	ipfsURL = "https://example.com/QmfDJowXchtehd8me75qy3qJsSRNf45dtS2h56y3gydaYm"
	wallet = make(map[string]string)
	wallet["toAddress"] = "0xE5738a339102945E2311A2e82cBEA4c509b20B99" //my metamask address
	generateWallet()
}

func sendRawTransaction(rawTx string) {
	client, err := ethclient.Dial(connection)
	if err != nil {
		fmt.Println(err.Error() + "@" + whereami.WhereAmI())
	}

	rawTxBytes, err := hex.DecodeString(rawTx)

	tx := new(types.Transaction)
	rlp.DecodeBytes(rawTxBytes, &tx)

	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		fmt.Println(err.Error() + "@" + whereami.WhereAmI())
	}

	fmt.Printf("tx sent: %s", tx.Hash().Hex()) // tx sent: 0xc429e5f128387d224ba8bed6885e86525e14bfdc2eb24b5e9c3351a1176fd81f
}

func createRawTransaction(wallet map[string]string) string {
	client, err := ethclient.Dial(connection)
	if err != nil {
		fmt.Println(err.Error() + "@" + whereami.WhereAmI())
	}

	privateKey, err := crypto.HexToECDSA(wallet["privateKey"])
	if err != nil {
		fmt.Println(err.Error() + "@" + whereami.WhereAmI())
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("error casting public key to ECDSA@" + whereami.WhereAmI())
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		fmt.Println(err.Error() + "@" + whereami.WhereAmI())
	}

	value := big.NewInt(1000000000000000000) // in wei (1 eth) 1000000000000000000
	gasLimit := uint64(21000)                // in units 21000
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		fmt.Println(err.Error() + "@" + whereami.WhereAmI())
	}
	fmt.Print("gasPrice: ")
	fmt.Println(gasPrice)

	toAddress := common.HexToAddress(wallet["toAddress"])
	var data []byte
	data = []byte(ipfsURL)
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		fmt.Println(err.Error() + "@" + whereami.WhereAmI())
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		fmt.Println("\n" + err.Error() + "@" + whereami.WhereAmI())
	}
	fmt.Print("signedTx: ")
	fmt.Println(signedTx)
	ts := types.Transactions{signedTx}
	b := new(bytes.Buffer)
	ts.EncodeIndex(0, b)
	rawTxBytes := b.Bytes()
	rawTxHex := hex.EncodeToString(rawTxBytes)
	fmt.Printf("rawTxHex: " + rawTxHex) // f86...772
	return rawTxHex
}

func generateWallet() {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println(err.Error() + "@" + whereami.WhereAmI())
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	//fmt.Println(hexutil.Encode(privateKeyBytes)[2:]) // fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19
	wallet["privateKey"] = hexutil.Encode(privateKeyBytes)[2:]

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("cannot assert type: publicKey is not of type *ecdsa.PublicKey" + "@" + whereami.WhereAmI())
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	//fmt.Println(hexutil.Encode(publicKeyBytes)[4:]) // 9a7df67f79246283fdc93af76d4f8cdd62c4886e8cd870944e817dd0b97934fdd7719d0810951e03418205868a5c1b40b192451367f28e0088dd75e15de40c05
	wallet["publicKey"] = hexutil.Encode(privateKeyBytes)[2:]

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	//fmt.Println(address) // 0x96216849c49358B10257cb55b28eA603c874b05E
	wallet["address"] = address

	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])
	//fmt.Println(hexutil.Encode(hash.Sum(nil)[12:])) // 0x96216849c49358b10257cb55b28ea603c874b05e
	wallet["hash"] = hexutil.Encode(hash.Sum(nil)[12:])
}
