package transip_client_go

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const baseUrl = "https://api.transip.nl/v6"
const label = "transip-client-go.%d"

type AuthParams struct {
	Login          string
	Label          string
	PrivateKey     []byte
	ReadOnly       bool
	GlobalKey      bool
	ExpirationTime string
	NoCache        bool
}

type Client struct {
	token      *string
	httpClient *http.Client
}

type authRequestBody struct {
	Login          string `json:"login"`
	Nonce          string `json:"nonce"`
	ReadOnly       bool   `json:"read_only"`
	ExpirationTime string `json:"expiration_time"`
	Label          string `json:"label"`
	GlobalKey      bool   `json:"global_key"`
}

type AuthResponseBody struct {
	Token string `json:"token"`
}

func Init(authParams *AuthParams) (*Client, error) {

	if authParams == nil {
		return nil, errors.New("authParams cannot be nil")
	}

	if authParams.Login == "" {
		return nil, errors.New("authParams.Login cannot be empty")
	}

	if authParams.PrivateKey == nil {
		return nil, errors.New("authParams.PrivateKey cannot be empty")
	}

	if authParams.Label == "" {
		authParams.Label = fmt.Sprintf("go-transip-client.%d", time.Now().UnixMicro())
	}

	token, err := getToken(authParams)
	if err != nil {
		return nil, err
	}

	return &Client{
		token: token,
		httpClient: &http.Client{
			Timeout: time.Second * 10,
		},
	}, nil

}

func getToken(authParams *AuthParams) (*string, error) {

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	jwtDir := filepath.Join(home, ".transip-client-go")
	tokenFile := filepath.Join(jwtDir, "token.jwt")
	if doCache := !authParams.NoCache; doCache {
		err = os.MkdirAll(jwtDir, 0755)
		if err != nil {
			return nil, err
		}

		// check an existing token first
		if _, err = os.Stat(tokenFile); err == nil {
			data, err := os.ReadFile(tokenFile)
			if err != nil {
				return nil, err
			}

			tokenString := string(data)
			expired, err := tokenExpired(tokenString)
			if err != nil {
				return nil, err
			}
			if !expired {
				return &tokenString, nil
			}
		}
	}

	body := &authRequestBody{
		Login:          authParams.Login,
		Nonce:          fmt.Sprintf("%x", time.Now().UnixMicro()),
		ReadOnly:       authParams.ReadOnly,
		ExpirationTime: authParams.ExpirationTime,
		Label:          authParams.Label,
		GlobalKey:      authParams.GlobalKey,
	}

	// Calculate the signature. We need this in the auth request.
	signature, err := getSignature(authParams.PrivateKey, body)
	if err != nil {
		return nil, err
	}

	rb, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/auth", baseUrl),
		strings.NewReader(string(rb)),
	)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Signature", signature)

	client := &http.Client{
		Timeout: time.Second * 10,
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(response.Body)

	resp, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 201 {
		return nil, errors.New(response.Status)
	}

	authResponseBody := &AuthResponseBody{}
	if err := json.Unmarshal(resp, authResponseBody); err != nil {
		return nil, err
	}

	token := authResponseBody.Token
	if doCache := !authParams.NoCache; doCache {
		_ = os.WriteFile(tokenFile, []byte(token), 0600)
	}

	return &token, nil
}

func getSignature(privateKey []byte, authRequestBody *authRequestBody) (string, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("failed to decode private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	bodyBytes, err := json.Marshal(authRequestBody)
	if err != nil {
		return "", err
	}
	pKey := key.(*rsa.PrivateKey)
	hash := sha512.Sum512(bodyBytes)

	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		pKey,
		crypto.SHA512,
		hash[:],
	)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func (c *Client) doRequest(method string, endPoint string, requestBody any, responseBody any) error {

	var requestBodyReader io.Reader
	if requestBody != nil {
		rb, err := json.Marshal(requestBody)
		if err != nil {
			log.Fatal(err)
		}
		requestBodyReader = strings.NewReader(string(rb))
	}

	url := fmt.Sprintf("%s/%s", baseUrl, endPoint)

	request, err := http.NewRequest(method, url, requestBodyReader)
	if err != nil {
		return err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", *c.token))

	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(response.Body)

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	if response.StatusCode >= http.StatusBadRequest {
		log.Fatal(fmt.Sprintf("API error: %s", response.Status))
	}

	if err := json.Unmarshal(body, responseBody); err != nil {
		return err
	}

	return nil
}

func tokenExpired(tokenString string) (bool, error) {

	token, _, err := new(jwt.Parser).ParseUnverified(
		tokenString,
		jwt.MapClaims{},
	)
	if err != nil {
		return false, err
	}

	claims := token.Claims.(jwt.MapClaims)

	exp, err := claims.GetExpirationTime()
	if err != nil {
		return false, err
	}

	// Consider expired if less than 5 minutes remain
	return time.Now().Add(2 * time.Minute).After(exp.Time), nil

}
