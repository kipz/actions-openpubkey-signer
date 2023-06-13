package opk

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"
)

type GetOIDCToken func(audience string) (*ActionsJWT, error)

type Claims struct {
	Audience string `json:"aud"`
}

type OIDCProvider interface {
	GetJWT(*Claims) (*ActionsJWT, error)
	GetPublicKey(string, string) (*rsa.PublicKey, error)
}

func Sign(payload *[]byte, provider OIDCProvider) (signature.SignerVerifier, *CIC, error) {
	privKey, err := cosign.GeneratePrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generating private key: %w", err)
	}
	sv, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}
	h := sha256.Sum256(*payload)
	sig, err := sv.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}
	// generate nonce
	rz := make([]byte, 32)
	rand.Read(rz)

	key, err := sv.PublicKey()
	if err != nil {
		return nil, nil, err
	}
	pem, err := PubToPem(key)
	if err != nil {
		return nil, nil, err
	}
	withSig := SHA512(rz, sig)
	cic := NewCIC("ES256", pem, withSig)
	return sv, cic, nil
}
func SignedOpenPubKey(payload *[]byte, provider OIDCProvider) (*OpenPubKey, error) {
	sv, cic, err := Sign(payload, provider)
	if err != nil {
		return nil, err
	}
	claims := &Claims{
		Audience: cic.Hash(),
	}
	token, err := provider.GetJWT(claims)
	if err != nil {
		return nil, err
	}
	return NewOpenPubKey(token, sv, cic), nil
}
