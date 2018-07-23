package jwt

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo"
	"gopkg.in/dgrijalva/jwt-go.v3"
)

// MapClaims type that uses the map[string]interface{} for JSON decoding
// This is the default claims type if you don't supply one
type MapClaims map[string]interface{}

// EchoJWTMiddleware provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the userID is made available as
// c.Get("userID").(string).
// Users can get a token by posting a json request to LoginHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX
type EchoJWTMiddleware struct {
	// Realm name to display to the user. Required.
	Realm string

	// signing algorithm - possible values are HS256, HS384, HS512
	// Optional, default is HS256.
	SigningAlgorithm string

	// Secret key used for signing. Required only if the asymmetric algorithm is not used
	Key []byte

	// Duration that a jwt token is valid. Optional, defaults to one hour.
	Timeout time.Duration

	// This field allows clients to refresh their token until MaxRefresh has passed.
	// Note that clients can refresh their token in the last moment of MaxRefresh.
	// This means that the maximum validity timespan for a token is MaxRefresh + Timeout.
	// Optional, defaults to 0 meaning not refreshable.
	MaxRefresh time.Duration

	// Callback function that should perform the authentication of the user based on userID and
	// password. Must return true on success, false on failure. Required.
	// Option return user data, if so, user data will be stored in Claim Array.
	Authenticator func(userID string, password string, c echo.Context) (interface{}, bool)

	// Callback function that should perform the authorization of the authenticated user. Called
	// only after an authentication success. Must return true on success, false on failure.
	// Optional, default to success.
	Authorizator func(data interface{}, c echo.Context) bool

	// Callback function that will be called during login.
	// Using this function it is possible to add additional payload data to the webtoken.
	// The data is then made available during requests via c.Get("JWT_PAYLOAD").
	// Note that the payload is not encrypted.
	// The attributes mentioned on jwt.io can't be used as keys for the map.
	// Optional, by default no additional data will be set.
	PayloadFunc func(data interface{}) MapClaims

	// User can define own Unauthorized func.
	Unauthorized func(echo.Context, int, string) error

	// User can define own LoginResponse func.
	LoginResponse func(echo.Context, int, string, time.Time) error

	// User can define own RefreshResponse func.
	RefreshResponse func(echo.Context, int, string, time.Time) error

	// Set the identity handler function
	IdentityHandler func(jwt.MapClaims) interface{}

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "cookie:<name>"
	TokenLookup string

	// TokenHeadName is a string in the header. Default value is "Bearer"
	TokenHeadName string

	// TimeFunc provides the current time. You can override it to use another time value. This is useful for testing or if your server uses a different time zone than your tokens.
	TimeFunc func() time.Time

	// HTTP Status messages for when something in the JWT middleware fails.
	// Check error (e) to determine the appropriate error message.
	HTTPStatusMessageFunc func(e error, c echo.Context) string

	// Private key file for asymmetric algorithms
	PrivKeyFile string

	// Public key file for asymmetric algorithms
	PubKeyFile string

	// Private key
	privKey *rsa.PrivateKey

	// Public key
	pubKey *rsa.PublicKey

	// Optionally return the token as a cookie
	SentCookie string

	// Allow insecure cookies for development over http
	SecureCookie bool

	DomainName string
}

var (
	// ErrMissingRealm indicates Realm name is required
	ErrMissingRealm = errors.New("realm is missing")

	// ErrMissingSecretKey indicates Secret key is required
	ErrMissingSecretKey = errors.New("secret key is required")

	// ErrForbidden when HTTP status 403 is given
	ErrForbidden = errors.New("you don't have permission to access this resource")

	// ErrMissingAuthenticatorFunc indicates Authenticator is required
	ErrMissingAuthenticatorFunc = errors.New("echoJWTMiddleware.Authenticator func is undefined")

	// ErrMissingLoginValues indicates a user tried to authenticate without username or password
	ErrMissingLoginValues = errors.New("missing Username or Password")

	// ErrFailedAuthentication indicates authentication failed, could be faulty username or password
	ErrFailedAuthentication = errors.New("incorrect Username or Password")

	// ErrFailedTokenCreation indicates JWT Token failed to create, reason unknown
	ErrFailedTokenCreation = errors.New("failed to create JWT Token")

	// ErrExpiredToken indicates JWT token has expired. Can't refresh.
	ErrExpiredToken = errors.New("token is expired")

	// ErrEmptyAuthHeader can be thrown if authing with a HTTP header, the Auth header needs to be set
	ErrEmptyAuthHeader = errors.New("auth header is empty")

	// ErrInvalidAuthHeader indicates auth header is invalid, could for example have the wrong Realm name
	ErrInvalidAuthHeader = errors.New("auth header is invalid")

	// ErrEmptyQueryToken can be thrown if authing with URL Query, the query token variable is empty
	ErrEmptyQueryToken = errors.New("query token is empty")

	// ErrEmptyCookieToken can be thrown if authing with a cookie, the token cokie is empty
	ErrEmptyCookieToken = errors.New("cookie token is empty")

	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid, needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

	// ErrNoPrivKeyFile indicates that the given private key is unreadable
	ErrNoPrivKeyFile = errors.New("private key file unreadable")

	// ErrNoPubKeyFile indicates that the given public key is unreadable
	ErrNoPubKeyFile = errors.New("public key file unreadable")

	// ErrInvalidPrivKey indicates that the given private key is invalid
	ErrInvalidPrivKey = errors.New("private key invalid")

	// ErrInvalidPubKey indicates the the given public key is invalid
	ErrInvalidPubKey = errors.New("public key invalid")
)

// Login form structure.
type Login struct {
	Username string `form:"username" json:"username" query:"required"`
	Password string `form:"password" json:"password" query:"required"`
}

func (mw *EchoJWTMiddleware) readKeys() error {
	err := mw.privateKey()
	if err != nil {
		return err
	}
	err = mw.publicKey()
	if err != nil {
		return err
	}
	return nil
}

func (mw *EchoJWTMiddleware) privateKey() error {
	keyData, err := ioutil.ReadFile(mw.PrivKeyFile)
	if err != nil {
		return ErrNoPrivKeyFile
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPrivKey
	}
	mw.privKey = key
	return nil
}

func (mw *EchoJWTMiddleware) publicKey() error {
	keyData, err := ioutil.ReadFile(mw.PubKeyFile)
	if err != nil {
		return ErrNoPubKeyFile
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	mw.pubKey = key
	return nil
}

func (mw *EchoJWTMiddleware) usingPublicKeyAlgo() bool {
	switch mw.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}

// MiddlewareInit initialize jwt configs.
func (mw *EchoJWTMiddleware) MiddlewareInit() error {

	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:Authorization"
	}

	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = "HS256"
	}

	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}

	if mw.TimeFunc == nil {
		mw.TimeFunc = time.Now
	}

	mw.TokenHeadName = strings.TrimSpace(mw.TokenHeadName)
	if len(mw.TokenHeadName) == 0 {
		mw.TokenHeadName = "Bearer"
	}

	if mw.Authorizator == nil {
		mw.Authorizator = func(data interface{}, c echo.Context) bool {
			return true
		}
	}

	if mw.Unauthorized == nil {
		mw.Unauthorized = func(c echo.Context, code int, message string) error {
			return c.JSON(code, map[string]interface{}{
				"code":    code,
				"message": message,
			})
		}
	}

	if mw.LoginResponse == nil {
		mw.LoginResponse = func(c echo.Context, code int, token string, expire time.Time) error {
			return c.JSON(http.StatusOK, map[string]interface{}{
				"code":   http.StatusOK,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	if mw.RefreshResponse == nil {
		mw.RefreshResponse = func(c echo.Context, code int, token string, expire time.Time) error {
			return c.JSON(http.StatusOK, map[string]interface{}{
				"code":   http.StatusOK,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	if mw.IdentityHandler == nil {
		mw.IdentityHandler = func(claims jwt.MapClaims) interface{} {
			return claims["id"]
		}
	}

	if mw.HTTPStatusMessageFunc == nil {
		mw.HTTPStatusMessageFunc = func(e error, c echo.Context) string {
			return e.Error()
		}
	}

	if mw.Realm == "" {
		return ErrMissingRealm
	}

	if mw.usingPublicKeyAlgo() {
		return mw.readKeys()
	}

	if mw.Key == nil {
		return ErrMissingSecretKey
	}
	return nil
}

func (mw *EchoJWTMiddleware) ParseToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		mw.parseToken(c)
		return next(c)
	}
}

func (mw *EchoJWTMiddleware) ForceAuthentication(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := c.Get("JWT_TOKEN_ERR"); err != nil {
			if e, ok := err.(error); ok {
				return mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(e, c))
			}
		}
		id := c.Get("USER_ID")
		if !mw.Authorizator(id, c) {
			return mw.unauthorized(c, http.StatusForbidden, mw.HTTPStatusMessageFunc(ErrForbidden, c))
		}

		return next(c)
	}
}

// LoginHandler can be used by clients to get a jwt token.
// Payload needs to be json in the form of {"username": "USERNAME", "password": "PASSWORD"}.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *EchoJWTMiddleware) LoginHandler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {

		var loginVals Login

		if c.Bind(&loginVals) != nil {
			return mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrMissingLoginValues, c))
		}

		if mw.Authenticator == nil {
			return mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(ErrMissingAuthenticatorFunc, c))
		}

		data, ok := mw.Authenticator(loginVals.Username, loginVals.Password, c)

		if !ok {
			return mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedAuthentication, c))
		}

		// Create the token
		token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
		claims := token.Claims.(jwt.MapClaims)

		if mw.PayloadFunc != nil {
			for key, value := range mw.PayloadFunc(data) {
				claims[key] = value
			}
		}

		if claims["id"] == nil {
			claims["id"] = loginVals.Username
		}

		expire := mw.TimeFunc().Add(mw.Timeout)
		claims["exp"] = expire.Unix()
		claims["iat"] = mw.TimeFunc().Unix()
		tokenString, err := mw.signedString(token)

		if err != nil {
			return mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedTokenCreation, c))
		}

		// set cookie
		if mw.SentCookie != "" {
			cookie := new(http.Cookie)
			cookie.Name = mw.SentCookie
			cookie.Value = tokenString
			cookie.Expires = expire
			cookie.Path = "/"
			cookie.Domain = mw.DomainName
			cookie.Secure = mw.SecureCookie
			cookie.HttpOnly = true
			c.SetCookie(cookie)
		}

		return mw.LoginResponse(c, http.StatusOK, tokenString, expire)
	}
}

func (mw *EchoJWTMiddleware) signedString(token *jwt.Token) (string, error) {
	var tokenString string
	var err error
	if mw.usingPublicKeyAlgo() {
		tokenString, err = token.SignedString(mw.privKey)
	} else {
		tokenString, err = token.SignedString(mw.Key)
	}
	return tokenString, err
}

// RefreshHandler can be used to refresh a token. The token still needs to be valid on refresh.
// Shall be put under an endpoint that is using the EchoJWTMiddleware.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *EchoJWTMiddleware) RefreshHandler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token, _ := mw.parseToken(c)
		claims := token.Claims.(jwt.MapClaims)

		origIat := int64(claims["iat"].(float64))

		if origIat < mw.TimeFunc().Add(-mw.MaxRefresh).Unix() {
			return mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
		}

		// Create the token
		newToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
		newClaims := newToken.Claims.(jwt.MapClaims)

		for key := range claims {
			newClaims[key] = claims[key]
		}

		expire := mw.TimeFunc().Add(mw.Timeout)
		newClaims["id"] = claims["id"]
		newClaims["exp"] = expire.Unix()
		newClaims["iat"] = mw.TimeFunc().Unix()
		tokenString, err := mw.signedString(newToken)

		if err != nil {
			return mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedTokenCreation, c))
		}

		// set cookie
		if mw.SentCookie != "" {
			cookie := new(http.Cookie)
			cookie.Name = mw.SentCookie
			cookie.Value = tokenString
			cookie.Expires = expire
			cookie.Path = "/"
			cookie.Domain = mw.DomainName
			cookie.Secure = mw.SecureCookie
			cookie.HttpOnly = true
			c.SetCookie(cookie)
		}

		return mw.RefreshResponse(c, http.StatusOK, tokenString, expire)
	}
}

// TokenGenerator method that clients can use to get a jwt token.
func (mw *EchoJWTMiddleware) TokenGenerator(userID string, data MapClaims) (string, time.Time, error) {
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			claims[key] = value
		}
	}

	expire := mw.TimeFunc().UTC().Add(mw.Timeout)
	claims["id"] = userID
	claims["exp"] = expire.Unix()
	claims["iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(token)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expire, nil
}

func (mw *EchoJWTMiddleware) jwtFromHeader(c echo.Context, key string) (string, error) {
	authHeader := c.Request().Header.Get(key)

	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == mw.TokenHeadName) {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

func (mw *EchoJWTMiddleware) jwtFromQuery(c echo.Context, key string) (string, error) {
	token := c.QueryParam(key)

	if token == "" {
		return "", ErrEmptyQueryToken
	}

	return token, nil
}

func (mw *EchoJWTMiddleware) jwtFromCookie(c echo.Context, key string) (string, error) {
	if cookie, err := c.Cookie(key); err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	return "", ErrEmptyCookieToken
}

func (mw *EchoJWTMiddleware) parseToken(c echo.Context) (*jwt.Token, error) {
	var token string
	var err error

	methods := strings.Split(mw.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token, err = mw.jwtFromHeader(c, v)
		case "query":
			token, err = mw.jwtFromQuery(c, v)
		case "cookie":
			token, err = mw.jwtFromCookie(c, v)
		}
	}

	if err != nil {
		c.Set("JWT_TOKEN_ERR", err)
		return nil, err
	}

	var t *jwt.Token
	if t, err = jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}

		return mw.Key, nil
	}); err == nil {
		// save token string if vaild
		c.Set("JWT_TOKEN", token)
		claims := t.Claims.(jwt.MapClaims)
		c.Set("JWT_PAYLOAD", claims)
		c.Set("USER_ID", mw.IdentityHandler(claims))

		return t, nil
	}
	c.Set("JWT_TOKEN_ERR", err)
	return nil, err
}

func (mw *EchoJWTMiddleware) unauthorized(c echo.Context, code int, message string) error {

	if mw.Realm == "" {
		mw.Realm = "echo jwt"
	}

	c.Request().Header.Set("WWW-Authenticate", "JWT realm="+mw.Realm)
	return mw.Unauthorized(c, code, message)
}

// ExtractClaims help to extract the JWT claims
func ExtractClaims(c echo.Context) jwt.MapClaims {
	claims := c.Get("JWT_PAYLOAD")
	if claims == nil {
		return make(jwt.MapClaims)
	}

	return claims.(jwt.MapClaims)
}

// GetToken help to get the JWT token string
func GetToken(c echo.Context) string {
	token := c.Get("JWT_TOKEN")
	if token == nil {
		return ""
	}

	return token.(string)
}
