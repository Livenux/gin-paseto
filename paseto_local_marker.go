package ginpaseto

import (
	"encoding/hex"
	"errors"
	"log"
	"time"

	"github.com/vk-rv/pvx"
)

type PasetoMaker struct {
	symmericKey *pvx.SymKey
	paseto      *pvx.ProtoV4Local
}

// NewPasetoMaker create paseto maker from ed25519 key
func NewPasetoMaker(key string) Maker {
	keyHex, err := hex.DecodeString(key)
	if err != nil {
		log.Fatal("cannot convert key string to maker []byte key")

	}
	symmericKey := pvx.NewSymmetricKey(keyHex, pvx.Version4)

	return &PasetoMaker{
		symmericKey: symmericKey,
		paseto:      pvx.NewPV4Local(),
	}
}

func (maker *PasetoMaker) CreateToken(claims *Claims) (string, error) {
	return maker.paseto.Encrypt(maker.symmericKey, claims)

}

func (maker *PasetoMaker) VerifyToken(token string) (*Claims, error) {
	claims := new(Claims)
	err := maker.paseto.Decrypt(token, maker.symmericKey).ScanClaims(claims)
	return claims, err
}

func (maker *PasetoMaker) RefreshToken(claims *Claims, duration time.Duration) (string, error) {
	if err := claims.Valid(); err != nil {
		if errors.Is(err, ErrTokenMaxRefresh) {
			return "", err
		}
	}
	claims.IssuedAt = time.Now().UTC()
	claims.ExpiredAt = time.Now().UTC().Add(duration)
	return maker.paseto.Encrypt(maker.symmericKey, claims)
}
