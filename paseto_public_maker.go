package ginpaseto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"github.com/vk-rv/pvx"
	"log"
	"time"
)

type PasetoPublicMaker struct {
	paseto        *pvx.ProtoV4Public
	asymPublicKey *pvx.AsymPublicKey
	asymSecretKey *pvx.AsymSecretKey
}

// NewPasetoPublicMaker create paseto maker from ed25519 key
func NewPasetoPublicMaker(ed25519PublicKey, ed25519PrivateKey string) Maker {
	publicKey, privateKey, err := LoadEd25519Key(ed25519PublicKey, ed25519PrivateKey)
	if err != nil {
		log.Fatalf("can't load ed25519 key-pair error: %v", err)
	}

	asymSecretKey := pvx.NewAsymmetricSecretKey(privateKey, pvx.Version4)
	asymPublicKey := pvx.NewAsymmetricPublicKey(publicKey, pvx.Version4)

	return &PasetoPublicMaker{
		paseto:        pvx.NewPV4Public(),
		asymPublicKey: asymPublicKey,
		asymSecretKey: asymSecretKey,
	}
}

func (maker *PasetoPublicMaker) CreateToken(claims *Claims) (string, error) {
	return maker.paseto.Sign(maker.asymSecretKey, claims)

}

func (maker *PasetoPublicMaker) VerifyToken(token string) (*Claims, error) {
	claims := new(Claims)
	err := maker.paseto.Verify(token, maker.asymPublicKey).ScanClaims(claims)
	return claims, err
}

func (maker *PasetoPublicMaker) RefreshToken(claims *Claims, duration time.Duration) (string, error) {
	if err := claims.Valid(); err != nil {
		if errors.Is(err, ErrTokenMaxRefresh) {
			return "", err
		}
	}
	claims.IssuedAt = time.Now().UTC()
	claims.ExpiredAt = time.Now().UTC().Add(duration)
	return maker.CreateToken(claims)
}

func (maker *PasetoPublicMaker) RevokeToken(claims *Claims) error {
	if err := claims.Valid(); err != nil {
		return err
	}
	claims.MaxRefreshAt = time.Now().UTC()
	_, err := maker.CreateToken(claims)
	return err
}

// LoadEd25519Key Load Edwards curve key-pair from key block string
func LoadEd25519Key(ed25519PublicKey, ed25519PrivateKey string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicBlock, err := hex.DecodeString(ed25519PublicKey)
	if err != nil {
		return nil, nil, err
	}
	privateBlock, err := hex.DecodeString(ed25519PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := ParseEdPublicKeyBlock(publicBlock)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := ParseEdPrivateKeyBlock(privateBlock)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

var (
	ErrNotEdPrivateKey = errors.New("key is not a valid Ed25519 private key")
	ErrNotEdPublicKey  = errors.New("key is not a valid Ed25519 public key")
)

// ParseEdPrivateKeyBlock parses a pem.Block.Bytes Edwards curve private key
func ParseEdPrivateKeyBlock(key []byte) (ed25519.PrivateKey, error) {
	var err error
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: key,
	}
	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return nil, err
	}

	var privateKey ed25519.PrivateKey
	var ok bool
	if privateKey, ok = parsedKey.(ed25519.PrivateKey); !ok {
		return nil, ErrNotEdPrivateKey
	}

	return privateKey, nil
}

// ParseEdPublicKeyBlock parses  a pem.Block.Bytes Edwards curve public key
func ParseEdPublicKeyBlock(key []byte) (ed25519.PublicKey, error) {
	var err error
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: key,
	}
	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, err
	}

	var publicKey ed25519.PublicKey
	var ok bool
	if publicKey, ok = parsedKey.(ed25519.PublicKey); !ok {
		return nil, ErrNotEdPublicKey
	}

	return publicKey, nil
}
