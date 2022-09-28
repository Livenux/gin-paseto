package ginpaseto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPayloadValid(t *testing.T) {
	var (
		data       = "test"
		expire     = time.Second
		maxRefresh = time.Second * 2
	)
	payload := NewClaims(expire, maxRefresh)
	payload.Data = data
	err := payload.Valid()
	assert.NoError(t, err)

	// let's token expired
	time.Sleep(time.Second * 2)
	err = payload.Valid()
	assert.EqualError(t, err, ErrTokenExpired.Error())

}
