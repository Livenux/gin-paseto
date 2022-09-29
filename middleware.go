package ginpaseto

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type ParetoMiddleware struct {
	Maker           Maker
	Claims          *Claims
	Expired         time.Duration
	MaxRefresh      time.Duration
	RefreshTokenURL string
	BaseLoginURL    string
	LogoutURL       string
	TokenHeadName   string
	TokenLookup     string
	CookieName      string
	CookieSameSite  http.SameSite
	SendCookie      bool
	SecureCookie    bool
	CookieHTTPOnly  bool
}

var (
	ErrNoAuthorizationHeader     = errors.New("no Authorization header or the Authorization header is empty")
	ErrAuthorizationHeaderFormat = errors.New("incorrectly formatted authorization header")
)

type Response struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Href    string `json:"href,omitempty"`
	Data    any    `json:"data,omitempty"`
}

type TokenResponse struct {
	Expire time.Time `json:"expire"`
	Token  string    `json:"token"`
}

// Authorization gin authorization middleware handler
func (pm *ParetoMiddleware) Authorization() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := pm.parseClaims(c)
		if err != nil {
			if errors.Is(err, ErrNoAuthorizationHeader) || errors.Is(err, ErrAuthorizationHeaderFormat) {
				c.JSON(http.StatusForbidden, Response{
					Code:    http.StatusForbidden,
					Message: err.Error(),
					Href:    pm.BaseLoginURL,
				})
				c.Abort()
				return
			}
			if errors.Is(err, ErrTokenMaxRefresh) {
				c.JSON(http.StatusUnauthorized, Response{
					Code:    http.StatusUnauthorized,
					Message: err.Error() + ", please re-login",
					Href:    pm.BaseLoginURL,
				})
				c.Abort()
				return
			}

			if errors.Is(err, ErrTokenExpired) {
				c.JSON(http.StatusUnauthorized, Response{
					Code:    http.StatusUnauthorized,
					Message: err.Error() + ", please refresh token",
					Href:    pm.RefreshTokenURL,
				})
				c.Abort()
				return
			}
			c.JSON(http.StatusUnauthorized, Response{
				Code:    http.StatusUnauthorized,
				Message: err.Error(),
			})
			c.Abort()
			return
		}
		c.Set("authData", claims.Data)
		c.Next()
	}
}

// LoginHandler from gin context get login data to claim create token
func (pm *ParetoMiddleware) LoginHandler(loginFunc func(c *gin.Context) (data any, err error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := loginFunc(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, Response{
				Code:    http.StatusBadRequest,
				Message: "login failed, " + err.Error(),
			})
			c.Abort()
			return
		}
		pm.Claims.Data = data

		token, err := pm.Maker.CreateToken(pm.Claims)
		// send cookie to client
		pm.setCookie(c, token)
		if err != nil {
			log.Printf("Create paseto token error: %v", err)
			c.JSON(http.StatusInternalServerError, Response{
				Code:    http.StatusInternalServerError,
				Message: "an unexpected condition was encountered",
			})
			c.Abort()
			return
		}
		c.JSON(http.StatusOK, Response{
			Code:    http.StatusOK,
			Message: "login successful",
			Data: TokenResponse{
				Expire: pm.Claims.ExpiredAt,
				Token:  token},
		})

	}
}

// RefreshToken refresh token before max refresh time
func (pm *ParetoMiddleware) RefreshToken() gin.HandlerFunc {
	return func(c *gin.Context) {

		claims, err := pm.parseClaims(c)
		if err != nil {
			if errors.Is(err, ErrNoAuthorizationHeader) || errors.Is(err, ErrAuthorizationHeaderFormat) {
				c.JSON(http.StatusForbidden, Response{
					Code:    http.StatusForbidden,
					Message: err.Error(),
					Href:    pm.BaseLoginURL,
				})
				return
			}
			if errors.Is(err, ErrTokenMaxRefresh) {
				c.JSON(http.StatusUnauthorized, Response{
					Code:    http.StatusUnauthorized,
					Message: err.Error() + ", please re-login",
					Href:    pm.BaseLoginURL,
				})
				return
			}

			if errors.Is(err, ErrTokenExpired) {
				token, err := pm.Maker.RefreshToken(claims, pm.Expired)

				if err == nil {
					c.JSON(http.StatusOK, Response{
						Code:    http.StatusOK,
						Message: "token is refreshed",
						Data:    TokenResponse{Token: token}})
				}
				return
			}

			c.JSON(http.StatusInternalServerError, Response{
				Code:    http.StatusInternalServerError,
				Message: "an unexpected condition was encountered",
			})
		} else {
			token, err := pm.Maker.RefreshToken(claims, pm.Expired)
			pm.setCookie(c, token)
			if err == nil {
				c.JSON(http.StatusOK, Response{
					Code:    http.StatusOK,
					Message: "token is refreshed",
					Data: TokenResponse{
						Expire: pm.Claims.ExpiredAt,
						Token:  token}})
			}
		}
	}
}

func (pm *ParetoMiddleware) LogOut() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := pm.parseClaims(c)
		if err == nil {
			err := pm.Maker.RevokeToken(claims)
			if err != nil {
				log.Printf("revoke paseto token error: %v", err)
				c.JSON(http.StatusInternalServerError, Response{
					Code:    http.StatusInternalServerError,
					Message: "an unexpected condition was encountered",
				})
				return
			}
			pm.revokeCookie(c)
			c.JSON(http.StatusOK, Response{
				Code:    http.StatusOK,
				Message: "token is revoke",
			})
			return
		}

		if err != nil {
			if errors.Is(err, ErrNoAuthorizationHeader) || errors.Is(err, ErrAuthorizationHeaderFormat) {
				c.JSON(http.StatusForbidden, Response{
					Code:    http.StatusForbidden,
					Message: err.Error(),
					Href:    pm.BaseLoginURL,
				})
				return
			}
			if errors.Is(err, ErrTokenMaxRefresh) {
				c.JSON(http.StatusUnauthorized, Response{
					Code:    http.StatusUnauthorized,
					Message: err.Error() + ", please re-login",
					Href:    pm.BaseLoginURL,
				})
				return
			}
		}

	}
}

func (pm *ParetoMiddleware) setCookie(c *gin.Context, token string) {
	if pm.SendCookie {
		if pm.CookieSameSite != 0 {
			c.SetSameSite(pm.CookieSameSite)
		}
		maxAge := int(pm.Claims.MaxRefreshAt.Unix() - pm.Claims.IssuedAt.Unix())

		c.SetCookie(pm.CookieName,
			token,
			maxAge,
			"/",
			pm.Claims.Audience,
			pm.SecureCookie,
			pm.CookieHTTPOnly,
		)
	}
}

func (pm *ParetoMiddleware) revokeCookie(c *gin.Context) {
	if pm.SendCookie {
		if pm.CookieSameSite != 0 {
			c.SetSameSite(pm.CookieSameSite)
		}
		c.SetCookie(pm.CookieName,
			"",
			-1,
			"/",
			pm.Claims.Audience,
			pm.SendCookie,
			pm.CookieHTTPOnly)
	}
}

// extractBearToken from header string get token string
func (pm *ParetoMiddleware) extractBearerToken(header string) (string, error) {
	if header == "" {
		return "", ErrNoAuthorizationHeader
	}

	token := strings.Split(header, " ")
	if len(token) != 2 {
		return "", ErrAuthorizationHeaderFormat
	}
	return token[1], nil
}

// parseClaims from gin http Authorization to Claims
func (pm *ParetoMiddleware) parseClaims(c *gin.Context) (*Claims, error) {
	header := c.Request.Header.Get("Authorization")
	token, err := pm.extractBearerToken(header)
	if err != nil {
		return nil, err
	}
	return pm.Maker.VerifyToken(token)
}
