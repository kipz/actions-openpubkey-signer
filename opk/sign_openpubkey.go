package opk

import (
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"
)

type SignerVerifier struct {
	Cert    []byte
	Chain   []byte
	IDToken ActionsJWT
	signature.SignerVerifier
	close func()
}

func openPubkeySigner() (*SignerVerifier, error) {
	privKey, err := cosign.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}
	sv, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	var k *Signer

	if k, err = NewSigner(sv); err != nil {
		return nil, fmt.Errorf("getting key from Fulcio: %w", err)
	}

	return &SignerVerifier{
		SignerVerifier: k,
		IDToken:        k.IDToken,
	}, nil
}

type Signer struct {
	IDToken ActionsJWT
	signature.SignerVerifier
}

func GetToken(signer signature.SignerVerifier, audience string) (*ActionsJWT, error) {
	c := DefaultOIDCClient(audience)
	jwt, err := c.GetJWT()
	QuitOnErr(err)

	jwt.Parse()
	return jwt, nil
}

func NewSigner(signer signature.SignerVerifier) (*Signer, error) {

	// generate nonce
	rz := make([]byte, 32)
	rand.Read(rz)

	key, err := signer.PublicKey()
	if err != nil {
		panic(err)
	}
	pem, err := PubToPem(key)
	if err != nil {
		panic(err)
	}
	cic := NewCIC("ES256", pem, rz)
	audience := cic.Hash()

	token, err := GetToken(signer, audience) // TODO, use the chain.
	if err != nil {
		return nil, fmt.Errorf("retrieving cert: %w", err)
	}

	f := &Signer{
		SignerVerifier: signer,
		IDToken:        *token,
	}

	return f, nil
}
