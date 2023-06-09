package main

import (
	"fmt"

	opk "github.com/kipz/actions-openpubkey-signer/opk"
)

func main() {
	c := opk.DefaultOIDCClient("foo")
	jwt, err := c.GetJWT()
	opk.QuitOnErr(err)

	jwt.Parse()
	fmt.Print(jwt.PrettyPrintClaims())
}
