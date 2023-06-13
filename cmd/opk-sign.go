package main

import (
	"fmt"
	"os"

	"github.com/kipz/actions-openpubkey-signer/opk"
)

func main() {
	input := os.Args[1]
	payload := []byte(input)
	jwt, err := opk.SignedOpenPubKey(&payload, &opk.GitHubOIDCProvider{})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signed OpenPubKey for input %s, %s\n", input, jwt)
}
