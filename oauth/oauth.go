package oauth

import (
	"net/http"
	"time"
	"strconv"
	"github.com/KestutisKazlauskas/go-oauth/errors"
	"github.com/federicoleon/golang-restclient/rest"
	"encoding/json"
)

const (
	headerXPublic = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXUserId = "X-User-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.ReQuestBuilder{
		BaseURL: "http://localhost:8080",
		TimeOut: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Id string `json:"id"`
	UserId int64 `json:"user_id"`
	ClienId int64 `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(headerXPublic) == "true"
}

func GetUserId() int64 {
	if request == nil {
		return nil 
	}

	userId, err := strconv.ParseInt(request.Header.Get(headerXUserId), 10, 64)
	if err != nil {
		return 0
	}

	return userId
}

func GetClienId() int64 {
	if request == nil {
		return nil 
	}

	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}

	return clientId

}

func Authenticate(request *http.Request) *errors.RestErr {
	if request == nil {
		return 0
	}

	cleanRequest(request)

	accessTokenId = request.URL.Query().Get(paramAccessToken)

	if accessTokenId == "" {
		return nil 
	}

	accessToken, err := getAccessToken(accessTokenId)
	if err != nil {
		return err
	}

	request.Header.Add(headerXUserId, fmt.Sprinf("%v",accessToken.UserId))
	request.Header.Add(headerXClientId, fmt.Sprinf("%v",accessToken.ClientId))

	return nil
} 

func cleanRequest(request *http.Request) {
	if request == nil {
		return 
	}

	request.Header.Del(headerXClientId)
	request.Header.Del(headerXUserId)
}

func getAccessToken(accessTokenId string)(*accessToken, *errors.RestErr) {
	response := oauthRestClient.Get("/oauth/access_token/%s", accessTokenId)

	//Tiemout happens
	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("Timeout on oauth api.", nil)
	}

	//Some errors hapens
	if response.StatusCode > 299 {
		var restErr errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return nil, errors.NewInternalServerError("Cant parse the error.", nil)
		}

		return nil, &restErr
	}

	var accessToken accessToken
	if err := json.Unmarshal(response.Bytes(), &accessToken); err != nil {
		return nil, errors.NewInternalServerError("Cant parse the accessToken response.", nil)
	}

	return &accessToken, nil 

}
