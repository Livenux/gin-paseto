package ginpaseto

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestMiddleware(t *testing.T) {
	r := gin.Default()
	key := randomString(64)
	middleware := ParetoMiddleware{
		Maker:           NewPasetoLocalMaker(key),
		Expired:         time.Second * 5,
		MaxRefresh:      time.Second * 10,
		RefreshTokenURL: "/refresh",
		BaseLoginURL:    "/login/base",
	}
	middleware.Claims = NewClaims(middleware.Expired, middleware.MaxRefresh, WithClaimsOption(
		"testIssuer", "testUser", "testAud"))
	r.POST(middleware.BaseLoginURL, middleware.LoginHandler(loginHandler))
	privateGroup := r.Group("/")
	privateGroup.Use(middleware.Authorization())
	privateGroup.GET("", func(c *gin.Context) {
		c.String(http.StatusOK, "hello world")
	})
	privateGroup.GET(middleware.RefreshTokenURL, middleware.RefreshToken())

	indexRequest, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)
	indexRecorder := httptest.NewRecorder()
	//r.ServeHTTP(indexRecorder, indexRequest)
	//assert.Equal(t, http.StatusForbidden, indexRecorder.Code)
	//t.Logf("unAuthorization body: %v\n", indexRecorder.Body)

	loginUser := `{"username": "admin", "password": "chan9eMe"}`
	loginRequest, err := http.NewRequest("POST", "/login/base", strings.NewReader(loginUser))
	assert.NoError(t, err)
	loginRecorder := httptest.NewRecorder()
	r.ServeHTTP(loginRecorder, loginRequest)
	t.Logf("login successful body: %s", loginRecorder.Body)
	tokenResponse := new(Response)
	err = json.Unmarshal(loginRecorder.Body.Bytes(), tokenResponse)
	assert.NoError(t, err)
	t.Logf("tokenResponse: %+v", tokenResponse)
	var data = tokenResponse.Data.(map[string]interface{})
	token := data["token"]
	t.Logf("token is :%s\n", token)
	indexRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	r.ServeHTTP(indexRecorder, indexRequest)
	assert.Equal(t, http.StatusOK, indexRecorder.Code)
	t.Logf("loginSuccess %s\n", indexRecorder.Body)

	refreshRequest, err := http.NewRequest("GET", middleware.RefreshTokenURL, nil)
	refreshRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	assert.NoError(t, err)
	refreshRecord := httptest.NewRecorder()
	r.ServeHTTP(refreshRecord, refreshRequest)
	assert.Equal(t, http.StatusOK, refreshRecord.Code)
	t.Logf("refresh token response: %s", refreshRecord.Body)

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

func randomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, length)
	rand.Read(b)
	return fmt.Sprintf("%x", b)[:length]
}

func TestParetoMiddleware_checkTokenError(t *testing.T) {
	r := gin.Default()

	key := randomString(64)
	authMiddleWare := ParetoMiddleware{
		Maker:           NewPasetoLocalMaker(key),
		Expired:         time.Second * 2,
		MaxRefresh:      time.Second * 5,
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

	authMiddleWare.TokenLookup = map[string]string{
		"header": authMiddleWare.TokenHeadName,
		"cookie": authMiddleWare.CookieName,
	}

	authMiddleWare.Claims = NewClaims(authMiddleWare.Expired, authMiddleWare.MaxRefresh)

	r.Use(authMiddleWare.Authorization())

	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "hello world")
	})

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Logf("error new request: %v", err)
	}
	noRecorder := httptest.NewRecorder()
	r.ServeHTTP(noRecorder, req)
	assert.Equal(t, http.StatusForbidden, noRecorder.Code)
	t.Logf("noRecoder response: %s", noRecorder.Body)
}
