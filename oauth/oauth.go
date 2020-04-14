package oauth

import (
	"net/http"
	"time"
	"strconv"
	"github.com/KestutisKazlauskas/go-utils/rest_errors"
	"github.com/federicoleon/golang-restclient/rest"
	"encoding/json"
	"fmt"
)

const (
	headerXPublic = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXUserId = "X-User-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Id string `json:"id"`
	UserId int64 `json:"user_id"`
	ClientId int64 `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(headerXPublic) == "true"
}

func GetUserId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	userId, err := strconv.ParseInt(request.Header.Get(headerXUserId), 10, 64)
	if err != nil {
		return 0
	}

	return userId
}

func GetClienId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}

	return clientId

}

func Authenticate(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := request.URL.Query().Get(paramAccessToken)

	if accessTokenId == "" {
		return nil 
	}

	accessToken, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status() == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXUserId, fmt.Sprintf("%v",accessToken.UserId))
	request.Header.Add(headerXClientId, fmt.Sprintf("%v",accessToken.ClientId))

	return nil
} 

func cleanRequest(request *http.Request) {
	if request == nil {
		return 
	}

	request.Header.Del(headerXClientId)
	request.Header.Del(headerXUserId)
}

func getAccessToken(accessTokenId string)(*accessToken, rest_errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))

	//Tiemout happens
	if response == nil || response.Response == nil {
		return nil, rest_errors.NewInternalServerError("Timeout on oauth api.", nil, nil)
	}

	//Some errors hapens
	if response.StatusCode > 299 {
		restErr, err := NewRestErrorFromBytes(response.Bytes())
		if err != nil {
			return nil, rest_errors.NewInternalServerError("Cant parse the error.", nil, nil)
		}

		return nil, &restErr
	}

	var accessToken accessToken
	if err := json.Unmarshal(response.Bytes(), &accessToken); err != nil {
		return nil, rest_errors.NewInternalServerError("Cant parse the accessToken response.", nil, nil)
	}

	return &accessToken, nil 

}
