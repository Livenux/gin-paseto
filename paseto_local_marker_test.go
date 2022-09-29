package ginpaseto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPasetoMaker_CreateToken(t *testing.T) {
	key := "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
	maker := NewPasetoLocalMaker(key)
	user := map[string]string{"user_id": "1", "user_name": "livenux"}
	claims := NewClaims(time.Second, time.Second*5)
	claims.Data = user
	token, err := maker.CreateToken(claims)
	assert.NoError(t, err)
	t.Logf("token: %s\n", token)
	claim, err := maker.VerifyToken(token)
	assert.NoError(t, err)
	t.Logf("claim: %+v\n", claim)

	time.Sleep(time.Second * 3)
	_, err = maker.VerifyToken(token)
	assert.ErrorIs(t, err, ErrTokenExpired)

}
