package ginpaseto

import (
	"encoding/hex"
	"errors"
	"log"
	"time"

	"github.com/vk-rv/pvx"
)

type PasetoLocalMaker struct {
	symmericKey *pvx.SymKey
	paseto      *pvx.ProtoV4Local
}

// NewPasetoLocalMaker create paseto maker from ed25519 key
func NewPasetoLocalMaker(key string) Maker {
	keyHex, err := hex.DecodeString(key)
	if err != nil {
		log.Fatal("cannot convert key string to maker []byte key")

	}
	symmericKey := pvx.NewSymmetricKey(keyHex, pvx.Version4)

	return &PasetoLocalMaker{
		symmericKey: symmericKey,
		paseto:      pvx.NewPV4Local(),
	}
}

func (maker *PasetoLocalMaker) CreateToken(claims *Claims) (string, error) {
	return maker.paseto.Encrypt(maker.symmericKey, claims)

}

func (maker *PasetoLocalMaker) VerifyToken(token string) (*Claims, error) {
	claims := new(Claims)
	err := maker.paseto.Decrypt(token, maker.symmericKey).ScanClaims(claims)
	return claims, err
}

func (maker *PasetoLocalMaker) RefreshToken(claims *Claims, duration time.Duration) (string, error) {
	if err := claims.Valid(); err != nil {
		if errors.Is(err, ErrTokenMaxRefresh) {
			return "", err
		}
	}
	claims.IssuedAt = time.Now().UTC()
	claims.ExpiredAt = time.Now().UTC().Add(duration)
	return maker.CreateToken(claims)
}

func (maker *PasetoLocalMaker) RevokeToken(claims *Claims) error {
	if err := claims.Valid(); err != nil {
		return err
	}
	claims.MaxRefreshAt = time.Now().UTC()
	_, err := maker.CreateToken(claims)
	return err
}
