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
	"github.com/gin-gonic/gin"
	"github.com/Livenux/gin-paseto"
)

func main() {
	key := "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
	maker := ginpaseto.NewPasetoLocalMaker(key)
	authMiddleware := ginpaseto.ParetoMiddleware{
		Maker:           NewPasetoLocalMaker(key),
		Expired:         time.Second * 5,
		MaxRefresh:      time.Second * 10,
		RefreshTokenURL: "/refresh",
		BaseLoginURL:    "/login/base",
		LogoutURL: "/logout",
	}
	r := gin.Default()
	authMiddleware.Claims = ginpaseto.NewClaims(authMiddleware.Expired,
		authMiddleware.MaxRefresh)
	r.POST(authMiddleware.BaseLoginURL, authMiddleware.LoginHandler(loginHandler))
	privateGroup := r.Group("/")
	privateGroup.Use(authMiddleware.Authorization())
	privateGroup.GET("", func(c *gin.Context) {
		c.String(http.StatusOK, "hello world")
	})
	privateGroup.GET(authMiddleware.RefreshTokenURL, 
		authMiddleware.RefreshToken())
	privateGroup.GET(authMiddleware.LogoutURL,
		authMiddleware.Logout())

}


type loginUser struct {
	Id       int64  `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
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
```