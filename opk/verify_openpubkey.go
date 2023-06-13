package opk

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/sigstore/sigstore/pkg/signature"
)

type OpenPubKey struct {
	Payload    string         `json:"payload"`
	Signatures []OPKSignature `json:"signatures"`
}

type OPKSignature struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

type CIC struct {
	Algorithm   string `json:"alg"`
	PublicKey   []byte `json:"pub"`
	RandomNoise []byte `json:"rz"`
}

func NewKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func PubToPem(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: b,
		},
	), nil
}

func PemToPub(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("could not decode PEM block from %q", pemBytes)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func PrivToPem(priv *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	))
}

func SHA512(things ...[]byte) []byte {
	sha := sha512.New()
	for _, thing := range things {
		sha.Write(thing)
	}
	return sha.Sum(nil)
}

func SHA256(things ...[]byte) []byte {
	sha := sha256.New()
	for _, thing := range things {
		sha.Write(thing)
	}
	return sha.Sum(nil)
}

func NewCIC(alg string, pub, noise []byte) *CIC {
	return &CIC{Algorithm: alg, PublicKey: pub, RandomNoise: noise}
}

func (c *CIC) Hash() string {
	sha := SHA512([]byte(c.Algorithm), c.RandomNoise)
	return hex.EncodeToString(sha)
}

func NewOpenPubKey(jwt *ActionsJWT, sv signature.SignerVerifier, cic *CIC) *OpenPubKey {
	header, _ := json.Marshal(jwt.ParsedToken.Header)
	opkHeader, _ := json.Marshal(cic)
	payload := jwt.ParsedToken.Raw
	opkSig, err := sv.SignMessage(bytes.NewBufferString(payload))
	if err != nil {
		panic(err)
	}
	return &OpenPubKey{
		Payload: payload,
		Signatures: []OPKSignature{
			{

				Protected: base64.RawURLEncoding.EncodeToString(header),
				Signature: jwt.ParsedToken.Signature,
			},
			{
				Protected: base64.RawURLEncoding.EncodeToString(opkHeader),
				Signature: base64.RawURLEncoding.EncodeToString(opkSig),
			},
		},
	}
}

func VerifyOPK(jwt *OpenPubKey, provider OIDCProvider, ids *[]Identity) error {
	payload, opkSignature := jwt.Payload, jwt.Signatures[1]

	cic, err := VerifyOPKSignature(opkSignature, payload)
	if err != nil {
		return fmt.Errorf("failed to verify opk signature: %w", err)
	}

	err = VerifyOIDCSignature(jwt.Signatures[0], payload, provider, ids)
	if err != nil {
		return fmt.Errorf("failed to verify oidc signature: %w", err)
	}
	err = verifyNonce(cic, payload)
	if err != nil {
		return fmt.Errorf("failed to verify nonce: %w", err)
	}
	return nil
}

func VerifyOPKSignature(sigWrapper OPKSignature, payload string) (*CIC, error) {
	protectedJSON, err := base64.RawURLEncoding.DecodeString(sigWrapper.Protected)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode protected: %w", err)
	}

	var protected CIC
	err = json.Unmarshal(protectedJSON, &protected)
	if err != nil {
		return nil, fmt.Errorf("failed to json decode our protected: %w", err)
	}

	if protected.Algorithm != "ES256" {
		return nil, fmt.Errorf("expected ES256 alg, got %q", protected.Algorithm)
	}

	pubKeyPEM := protected.PublicKey
	pubKey, err := PemToPub(pubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode our public key: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigWrapper.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode our signature: %w", err)
	}

	verifier, err := signature.LoadECDSAVerifier(pubKey.(*ecdsa.PublicKey), crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to LoadECDSAVerifier: %w", err)
	}

	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader([]byte(payload)))
	if err != nil {
		return nil, fmt.Errorf("failed to verify our signature: %w", err)
	}

	fmt.Println("✅ Verified signing key in OPK was used to sign OPK payload")

	return &protected, nil
}

type Identity struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

func GetOIDCPublicKey(issueUrl string, kid string) (*rsa.PublicKey, error) {
	fmt.Println("🔎 Fetching OIDC discovery URL: %w", issueUrl)

	oidcDiscResp, err := http.Get(issueUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to OIDC discovery URL: %w", err)
	}

	defer oidcDiscResp.Body.Close()

	if oidcDiscResp.StatusCode != 200 {
		return nil, fmt.Errorf("got %v from OIDC discovery URL", oidcDiscResp.StatusCode)
	}

	var oidcResp map[string]any
	decoder := json.NewDecoder(oidcDiscResp.Body)
	err = decoder.Decode(&oidcResp)
	if err != nil {
		return nil, fmt.Errorf("failed to json decode payload: %w", err)
	}

	jwksURI := oidcResp["jwks_uri"].(string)
	fmt.Println("🔎 Fetching JWKS URL: %w", jwksURI)

	jwks, err := jwk.Fetch(context.TODO(), jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}

	key, ok := jwks.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("couldn't find key %q in JWKS", kid)
	}

	var pubKey rsa.PublicKey
	err = key.Raw(&pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA key: %w", err)
	}
	return &pubKey, nil
}

func VerifyOIDCSignature(sigWrapper OPKSignature, payloadStr string, provider OIDCProvider, ids *[]Identity) error {
	protectedJSON, err := base64.RawURLEncoding.DecodeString(sigWrapper.Protected)
	if err != nil {
		return fmt.Errorf("failed to base64 decode protected: %w", err)
	}
	fmt.Printf("🔎 Decoded protected: %s\n", string(protectedJSON))
	var protected map[string]string
	err = json.Unmarshal(protectedJSON, &protected)
	if err != nil {
		return fmt.Errorf("failed to json decode their protected: %w", err)
	}
	fmt.Printf("🔎 Unmarshalled protected: %s\n", protected)

	if protected["alg"] != "RS256" {
		return fmt.Errorf("expected RS256 alg")
	}
	fmt.Printf("🔎 Got alg %s\n", protected["alg"])
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadStr)
	if err != nil {
		return fmt.Errorf("failed to base64 decode payload: %w", err)
	}
	fmt.Printf("🔎 Decoded payload: %s\n", string(payloadJSON))
	var payload map[string]any
	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return fmt.Errorf("failed to json decode payload: %w", err)
	}

	issuer := payload["iss"].(string)
	issuerUrl, err := url.JoinPath(issuer, ".well-known/openid-configuration")
	if err != nil {
		return fmt.Errorf("failed to construct OIDC discovery URI: %w", err)
	}
	fmt.Printf("🔎 Got issuer %s\n", issuer)
	pubKey, err := provider.GetPublicKey(issuerUrl, protected["kid"])
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigWrapper.Signature)
	if err != nil {
		return fmt.Errorf("failed to base64 decode signature: %w", err)
	}

	fmt.Println("🔎 Hashing input: ", sigWrapper.Protected, ".", payloadStr)
	signingInput := fmt.Sprint(sigWrapper.Protected, ".", payloadStr)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, SHA256([]byte(signingInput)), sig)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	fmt.Println("✅ Verified OIDC payload was signed by", issuer)

	subject := payload["sub"].(string)
	if len(*ids) > 0 {
		for _, id := range *ids {
			if id.Issuer == issuer && id.Subject == subject {
				return nil
			}
		}
		return fmt.Errorf("none of the expected identities matched what was in the ID token, got %s from %s", subject, issuer)
	}

	return nil
}

func verifyNonce(cic *CIC, payloadStr string) error {
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadStr)
	if err != nil {
		return fmt.Errorf("failed to base64 decode payload: %w", err)
	}

	var payload map[string]any
	err = json.Unmarshal(payloadJSON, &payload)
	fmt.Println("🔎 Unmarshalled payload")
	if err != nil {
		return fmt.Errorf("failed to json decode payload: %w", err)
	}
	fmt.Println("🔎 Verifying nonce in OIDC payload")
	nonce := payload["nonce"].(string)

	if nonce != cic.Hash() {
		return fmt.Errorf("nonce doesn't match")
	}

	fmt.Println("✅ Verified nonce in OIDC payload matches header")
	return nil
}
