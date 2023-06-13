package opk

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt"
)

type Validator struct {
}

func (v *Validator) Valid() error {
	return nil
}

const testIssuer = "http://localhost:3000"

type IDToken struct {
	Issuer  string `json:"iss"`
	Nonce   string `json:"nonce"`
	Subject string `json:"sub"`
}

type LocalSelfSignedOIDCProvider struct {
	Identities *[]Identity
	Key        *rsa.PrivateKey
}

func (p *LocalSelfSignedOIDCProvider) GetJWT(claims *Claims) (*ActionsJWT, error) {
	idToken := IDToken{
		Issuer:  testIssuer,
		Nonce:   claims.Audience,
		Subject: "kipz/actions-openpubkey-signer",
	}
	js, _ := json.Marshal(idToken)
	raw := base64.RawURLEncoding.EncodeToString(js)

	header := map[string]interface{}{"alg": "RS256", "typ": "JWT", "kid": "somekid"}
	protectedJs, _ := json.Marshal(header)
	protected := base64.RawURLEncoding.EncodeToString(protectedJs)
	signingInput := fmt.Sprint(protected, ".", raw)
	h := SHA256([]byte(signingInput))
	sig, _ := p.Key.Sign(rand.Reader, h[:], crypto.SHA256)
	return &ActionsJWT{
		Count: 1,
		Value: "someval",
		ParsedToken: &jwt.Token{
			Header:    header,
			Raw:       raw,
			Signature: base64.RawURLEncoding.EncodeToString(sig),
		},
	}, nil
}

func (p *LocalSelfSignedOIDCProvider) GetPublicKey(issueUrl string, kid string) (*rsa.PublicKey, error) {
	return &p.Key.PublicKey, nil
}
func TestSigning(t *testing.T) {
	ids := &[]Identity{
		{
			Subject: "kipz/actions-openpubkey-signer",
			Issuer:  testIssuer,
		},
	}
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	provider := &LocalSelfSignedOIDCProvider{
		Identities: ids,
		Key:        k,
	}
	toSign := []byte("hello")
	jwt, _ := SignedOpenPubKey(&toSign, provider)

	err := VerifyOPK(jwt, provider, ids)
	if err != nil {
		t.Errorf("Failed to verify signature: %s", err)
	}
}
