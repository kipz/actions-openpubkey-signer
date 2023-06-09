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

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/sigstore/cosign/v2/pkg/cosign"

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

func NewOpenPubKey(parsedToken map[string]any, sv signature.SignerVerifier, cic *CIC) *OpenPubKey {
	header, _ := json.Marshal(parsedToken["header"].(map[string]any))
	opkHeader, _ := json.Marshal(cic)
	payload := parsedToken["rawPayload"].(string)
	opkSig, err := sv.SignMessage(bytes.NewBufferString(payload))
	if err != nil {
		panic(err)
	}
	return &OpenPubKey{
		Payload: payload,
		Signatures: []OPKSignature{
			{

				Protected: base64.RawURLEncoding.EncodeToString(header),
				Signature: parsedToken["signature"].(string),
			},
			{
				Protected: base64.RawURLEncoding.EncodeToString(opkHeader),
				Signature: base64.RawURLEncoding.EncodeToString(opkSig),
			},
		},
	}
}

func ValidateOPK(idToken []byte, co *cosign.CheckOpts) (signature.Verifier, error) {
	var opk OpenPubKey
	err := json.Unmarshal(idToken, &opk)
	if err != nil {
		return nil, fmt.Errorf("failed to json decode OPK: %w", err)
	}

	payload, ourSigWrapper, theirSigWrapper := opk.Payload, opk.Signatures[1], opk.Signatures[0]

	verifier, cic, err := verifyOurSigWrapper(ourSigWrapper, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to verify our signature: %w", err)
	}

	err = verifyTheirSigWrapper(theirSigWrapper, payload, co)
	if err != nil {
		return nil, fmt.Errorf("failed to verify their signature: %w", err)
	}

	err = verifyNonce(cic, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to verify nonce: %w", err)
	}

	return verifier, nil
}

func verifyOurSigWrapper(sigWrapper OPKSignature, payload string) (signature.Verifier, *CIC, error) {
	protectedJSON, err := base64.RawURLEncoding.DecodeString(sigWrapper.Protected)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to base64 decode protected: %w", err)
	}

	var protected CIC
	err = json.Unmarshal(protectedJSON, &protected)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to json decode our protected: %w", err)
	}

	if protected.Algorithm != "ES256" {
		return nil, nil, fmt.Errorf("expected ES256 alg, got %q", protected.Algorithm)
	}

	pubKeyPEM := protected.PublicKey
	pubKey, err := PemToPub(pubKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode our public key: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigWrapper.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to base64 decode our signature: %w", err)
	}

	verifier, err := signature.LoadECDSAVerifier(pubKey.(*ecdsa.PublicKey), crypto.SHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to LoadECDSAVerifier: %w", err)
	}

	err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader([]byte(payload)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify our signature: %w", err)
	}

	fmt.Println("✅ Verified signing key in OPK was used to sign OPK payload")

	return verifier, &protected, nil
}

func verifyTheirSigWrapper(sigWrapper OPKSignature, payloadStr string, co *cosign.CheckOpts) error {
	protectedJSON, err := base64.RawURLEncoding.DecodeString(sigWrapper.Protected)
	if err != nil {
		return fmt.Errorf("failed to base64 decode protected: %w", err)
	}

	// TODO: use a struct here
	var protected map[string]string
	err = json.Unmarshal(protectedJSON, &protected)
	if err != nil {
		return fmt.Errorf("failed to json decode their protected: %w", err)
	}

	if protected["alg"] != "RS256" {
		return fmt.Errorf("expected RS256 alg")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadStr)
	if err != nil {
		return fmt.Errorf("failed to base64 decode payload: %w", err)
	}

	var payload map[string]any
	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return fmt.Errorf("failed to json decode payload: %w", err)
	}

	issuer := payload["iss"].(string)
	oidcDiscURI, err := url.JoinPath(issuer, ".well-known/openid-configuration")
	if err != nil {
		return fmt.Errorf("failed to construct OIDC discovery URI: %w", err)
	}

	oidcDiscResp, err := http.Get(oidcDiscURI)
	if err != nil {
		return fmt.Errorf("failed to make request to OIDC discovery URL: %w", err)
	}

	defer oidcDiscResp.Body.Close()

	if oidcDiscResp.StatusCode != 200 {
		return fmt.Errorf("got %v from OIDC discovery URL", oidcDiscResp.StatusCode)
	}

	var oidcResp map[string]any
	decoder := json.NewDecoder(oidcDiscResp.Body)
	err = decoder.Decode(&oidcResp)
	if err != nil {
		return fmt.Errorf("failed to json decode payload: %w", err)
	}

	jwksURI := oidcResp["jwks_uri"].(string)

	jwks, err := jwk.Fetch(context.TODO(), jwksURI)
	if err != nil {
		return fmt.Errorf("failed to fetch to JWKS: %w", err)
	}

	key, ok := jwks.LookupKeyID(protected["kid"])
	if !ok {
		return fmt.Errorf("couldn't find key %q in JWKS", protected["kid"])
	}

	var pubKey rsa.PublicKey
	err = key.Raw(&pubKey)
	if err != nil {
		return fmt.Errorf("failed to decode RSA key: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigWrapper.Signature)
	if err != nil {
		return fmt.Errorf("failed to base64 decode signature: %w", err)
	}

	signingInput := fmt.Sprint(sigWrapper.Protected, ".", payloadStr)

	err = rsa.VerifyPKCS1v15(&pubKey, crypto.SHA256, SHA256([]byte(signingInput)), sig)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	fmt.Println("✅ Verified OIDC payload was signed by", issuer)

	subject := payload["email"].(string)
	if len(co.Identities) > 0 {
		for _, id := range co.Identities {
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
	if err != nil {
		return fmt.Errorf("failed to json decode payload: %w", err)
	}

	nonce := payload["nonce"].(string)

	if nonce != cic.Hash() {
		return fmt.Errorf("nonce doesn't match")
	}

	fmt.Println("✅ Verified nonce in OIDC payload matches header")

	return nil
}
