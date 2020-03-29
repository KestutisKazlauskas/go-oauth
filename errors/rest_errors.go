package errors
import (
	"net/http"
	"github.com/KestutisKazlauskas/go-oauth/logger"
)

type RestErr struct {
	Message string  `json:"message"`
	Status 	int 	`json:"status"`
	Error 	string 	`json:"error"`
}

func NewBadRequestError(message string) *RestErr {
	error := RestErr{
		Message: message,
		Status: http.StatusBadRequest,
		Error: "bad_request",
	}

	return &error
}

func NewNotFoundError(message string) *RestErr {
	error := RestErr{
		Message: message,
		Status: http.StatusNotFound,
		Error: "not_found",
	}

	return &error
}

func NewInternalServerError(logMessage string, err error) *RestErr {
	logger.Error(logMessage, err)
	error := RestErr{
		Message: "Something went wrong.",
		Status: http.StatusInternalServerError,
		Error: "internal_server_error",
	}

	return &error
}