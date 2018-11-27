package jwt

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	stdjwt "github.com/dgrijalva/jwt-go"
)

// AtlassianJWTClaims defines the Atlassian Connect version of a JWT Claims object
type AtlassianJWTClaims struct {
	stdjwt.StandardClaims
	Context   struct{} `json:"context"`
	QueryHash string   `json:"qsh"`
}

// Encode is used to make an Atlassian Connect compatible signed JWT token.
func Encode(link, contextPath, addOnKey string, signingKey []byte) (token string, err error) {

	var claims = AtlassianJWTClaims{}

	claims.StandardClaims = stdjwt.StandardClaims{
		Issuer:    addOnKey,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(3 * time.Minute).Unix(),
	}

	claims.QueryHash, err = getQueryHash(link, contextPath)
	if err != nil {
		return
	}

	unsignedToken := stdjwt.NewWithClaims(stdjwt.SigningMethodHS256, claims)

	token, err = unsignedToken.SignedString(signingKey)
	if err != nil {
		return
	}
	return
}

// Decode is used to verify an Atlassian Connect signed JWT token.
// If the token is valid but the shared secret does not match,
// then the function returns both a valid claims as well as the invalid signature error.
func Decode(tokenString, sharedSecret string) (claims *AtlassianJWTClaims, err error) {

	fn := func(token *stdjwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*stdjwt.SigningMethodHMAC); !ok {
			err = errors.New("incorrect signing method")
			return nil, err
		}
		return []byte(sharedSecret), nil
	}

	token, err := stdjwt.ParseWithClaims(tokenString, &AtlassianJWTClaims{}, fn)
	if err != nil && (err.Error() != "signature is invalid") {
		return
	}

	claims, ok := token.Claims.(*AtlassianJWTClaims)
	if !ok {
		err = errors.New("unable to convert token to atlassian-jwt claims")
		return
	}

	return
}

func getQueryHash(link, contextPath string) (queryHash string, err error) {

	var (
		query string
		merge []string
	)

	// If other methods are required take this as a fn argument.
	method := "GET"

	u, err := url.Parse(link)
	if err != nil {
		return
	}

	if contextPath != "" && (!strings.HasPrefix(u.Path, contextPath) || !strings.HasPrefix(contextPath, "/") || strings.HasSuffix(contextPath, "/")) {
		err = errors.New("invalid context path")
		return
	}

	u.Path = strings.TrimPrefix(u.Path, contextPath)

	if u.Path == "" {
		u.Path = "/"
	}

	if u.Path != "/" {
		u.Path = strings.TrimRight(u.Path, "/")
	}

	urlVals := u.Query()
	delete(urlVals, "jwt")

	for k, v := range urlVals {
		urlVals[k] = []string{strings.Join(v, ",")}
	}

	query = urlVals.Encode()

	query = strings.Replace(query, "+", "%20", -1)

	merge = []string{method, u.Path, query}

	canReq := strings.Join(merge, "&")

	sha := sha256.Sum256([]byte(canReq))

	queryHash = fmt.Sprintf("%x", sha)

	return
}
