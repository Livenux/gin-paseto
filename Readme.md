# Gin PASETO token middleware

This is a middleware for Gin framework.

It uses [pvx](https://github.com/vk-rv/pvx) to provide a PASETO authentication middleware. 
Currently, middleware supports paseto version 4 local and public.


## Usage

Download and install using [go module](https://blog.golang.org/using-go-modules):
``` shell
export GO111MODULE=on
go get -u github.com/Livenux/gin-paseto
```

Import it in your code:

```go
import "github.com/Livenux/ginpaseto"
```


## Example
### Claims
claims are pieces of information asserted about a subject.

Create Claims simple
```go
clamis := ginpaseto.NewClaims(time.Hour * 1, time.Hour*24)

```
Create Claims with option(_Issuer_, _Subject_, _Audience_)

```go
clamis := ginpaseto.NewClaims(time.Hour * 1, time.Hour*24,
 ginpaeto.WithClaimsOption("api.example.com", 
	 "authToken", "web.example.com"))
```

### Local PASETO
```go
package main

import (
	"errors"
	"net/http"
	"time"

	ginpaseto "github.com/Livenux/gin-paseto"
	"github.com/gin-gonic/gin"
)

func main() {
	// hex string key
	key := "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
	maker := ginpaseto.NewPasetoLocalMaker(key)
	authMiddleware := ginpaseto.PasetoMiddleware{
		Issuer:       "api.example.com",
		Subject:      "authToken",
		Audience:     ".example.com",
		Expired:         time.Hour * 2,  // token expired
		MaxRefresh:      time.Hour * 24, // token max age
		RefreshTokenURL: "/auth/refresh",
		BaseLoginURL:    "/auth/login",
		LogoutURL:       "/auth/logout",
		TokenHeadName:   "Authorization",
		CookieName:      "auth",
		CookieSameSite:  1,
		SendCookie:      false,
		SecureCookie:    false,
		CookieHTTPOnly:  false,
	}
	// Completion property
	authMiddleware.Init(maker)



	r := gin.Default()

	// binding login handler
	r.POST(authMiddleware.BaseLoginURL, authMiddleware.LoginHandler(loginHandler))

	// need auth router group
	privateGroup := r.Group("/")
	privateGroup.Use(authMiddleware.Authorization())
	privateGroup.GET("", func(c *gin.Context) {
		c.String(http.StatusOK, "hello world")
	})
	// refresh token route
	privateGroup.GET(authMiddleware.RefreshTokenURL, authMiddleware.RefreshToken())
	// logout route
	privateGroup.GET(authMiddleware.LogoutURL, authMiddleware.LogOut())

	r.Run()

}

func loginHandler(c *gin.Context) (data any, err error) {
	user := loginUser{
		Id:       1,
		Username: "admin",
		Password: "chan9eMe",
	}
	requestUser := new(loginUser)
	if err := c.ShouldBindJSON(requestUser); err != nil {
		return nil, err
	}

	if requestUser.Username == user.Username && requestUser.Password == user.Password {
		return user, nil
	}
	return nil, errors.New("auth failed")

}

type loginUser struct {
	Id       int64  `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}
```


example start
```shell
go run main.go
```

login example user get token
```shell
 curl -XPOST -d '{"username": "admin", "password": "chan9eMe"}' -H "Content-Type: application/json" http://localhos
t:8080/auth/login
```
response token example:
```shell
{"code":200,"message":"login successful","data":{"expire":"2022-09-30T18:21:48.09772Z","token":"v4.local.qLBoiHYgkE19moyOZ0PcvhLUKTlx2QGQQ3EQ6TTLDBGMPrmqAd1jHNAf6iz6-RqAe90YFtNkWQIU3amhKPGlyyH9vKCb2pkPoW_oxft1_Q9yZzSwpuovg6Vs3xyv3eoVU8c-FepXzfcOfkNW6zUfe_WJGjAAxKn23LyO8p9wiFdRpGtzFOzlSF7nVm_iX_KZRNyQ4-91wMbm_1EUHNc3f7Jsk5mfaEWKKRP1Ez6a3A2dvQGMibPTakgpS4gmHyradbXViBKaUlkbFVX5-Qb27d1CUWu5-bIG-yOLpDgnZt7rTsOx79IkVNW29J4PEJXID_UgQzX2kXD-EN5D"}}
```
refresh token use exists token:
```shell
curl -XGET -H "Authorization: Bearer v4.local.qLBoiHYgkE19moyOZ0PcvhLUKTlx2QGQQ3EQ6TTLDBGMPrmqAd1jHNAf6iz6-RqAe90YFtNkWQIU3amhKPGlyyH9vKCb2pkPoW_oxft1_Q9yZzSwpuovg6Vs3xyv3eoVU8c-FepXzfcOfkNW6zUfe_WJGjAAxKn23LyO8p9wiFdRpGtzFOzlSF7nVm_iX_KZRNyQ4-91wMbm_1EUHNc3f7Jsk5mfaEWKKRP1Ez6a3A2dvQGMibPTakgpS4gmHyradbXViBKaUlkbFVX5-Qb27d1CUWu5-bIG-yOLpDgnZt7rTsOx79IkVNW29J4PEJXID_UgQzX2kXD-EN5D" http://localhost:8080/auth/refresh
```

