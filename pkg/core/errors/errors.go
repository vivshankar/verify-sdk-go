package error

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ibm-verify/verify-sdk-go/pkg/i18n"
)

type VerifyError struct {
	MessageID          string `json:"messageId" yaml:"messageId"`
	MessageDescription string `json:"messageDescription" yaml:"messageDescription"`
}

func (e *VerifyError) Error() string {
	return fmt.Sprintf("%s %s", e.MessageID, e.MessageDescription)
}

func G11NError(message string, args ...any) error {
	return fmt.Errorf("%s", i18n.TranslateWithArgs(message, args...))
}

func HandleCommonErrors(ctx context.Context, response *http.Response, defaultError string) error {
	if response.StatusCode == http.StatusUnauthorized {
		return G11NError("login again")
	}

	if response.StatusCode == http.StatusForbidden {
		return G11NError("you are not allowed to make this request. Check the client or application entitlements")
	}

	if response.StatusCode == http.StatusBadRequest {
		var errorMessage VerifyError
		body, _ := io.ReadAll(response.Body)

		if err := json.Unmarshal(body, &errorMessage); err != nil {
			return G11NError("bad request: %s", defaultError)
		}
		// If the expected fields are not populated, return the raw response body.
		if errorMessage.MessageID == "" && errorMessage.MessageDescription == "" {
			return G11NError("bad request: %s", string(body))
		}
		return &errorMessage
	}

	if response.StatusCode == http.StatusNotFound {
		return G11NError("resource not found")
	}

	return nil
}
