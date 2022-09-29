package ginpaseto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
	"time"
)

func TestLoadEd25519Key(t *testing.T) {
	_, _, err := LoadEd25519Key(createEd25519KeyPairString())
	assert.NoError(t, err)
}

func TestNewPasetoPublicMaker(t *testing.T) {
	publicKey, privateKey := createEd25519KeyPairString()
	maker := NewPasetoPublicMaker(publicKey, privateKey)
	claims := NewClaims(time.Second*2, time.Second*5)
	user := map[string]int{"user_id": 1}
	claims.Data = user
	_, err := maker.CreateToken(claims)
	assert.NoError(t, err)

	refreshToken, err := maker.RefreshToken(claims, time.Second*2)
	assert.NoError(t, err)

	rClaims, err := maker.VerifyToken(refreshToken)
	assert.NoError(t, err)
	claimsSub := rClaims.IssuedAt.Sub(claims.IssuedAt)
	assert.GreaterOrEqual(t, time.Second*2, claimsSub)

	time.Sleep(time.Second * 6)
	_, err = maker.VerifyToken(refreshToken)
	assert.ErrorIs(t, err, ErrTokenMaxRefresh)

}

// createEd25519KeypairString create Edwards curve key-pair return pem block string
func createEd25519KeyPairString() (publicKey string, privateKey string) {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)
	publicBytes, err := x509.MarshalPKIXPublicKey(publicRoot)
	if err != nil {
		log.Fatalf("marshal ed25519 public key err: %v", err)
	}
	privateBytes, err := x509.MarshalPKCS8PrivateKey(privateRoot)
	if err != nil {
		log.Fatalf("marshal ed25519 private key err: %v", err)
	}

	publicOut := new(bytes.Buffer)
	privateOut := new(bytes.Buffer)

	if err := pem.Encode(publicOut, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}); err != nil {
		log.Fatalf("failed encode public key to writer, err: %v", err)
	}

	if err := pem.Encode(privateOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateBytes,
	}); err != nil {
		log.Fatalf("failed encode private key to writer, err: %v", err)

	}

	privateBlock, _ := pem.Decode(privateOut.Bytes())
	privateKey = hex.EncodeToString(privateBlock.Bytes)
	publicBlock, _ := pem.Decode(publicOut.Bytes())
	publicKey = hex.EncodeToString(publicBlock.Bytes)
	return
}
