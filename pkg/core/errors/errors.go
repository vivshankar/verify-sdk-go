package error

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type VerifyError struct {
	MessageID          string `json:"messageId" yaml:"messageId"`
	MessageDescription string `json:"messageDescription" yaml:"messageDescription"`
}

func (e *VerifyError) Error() string {
	return fmt.Sprintf("%s %s", e.MessageID, e.MessageDescription)
}

func HandleCommonErrors(ctx context.Context, response *http.Response, defaultError string) error {
	if response.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("login again")
	}

	if response.StatusCode == http.StatusForbidden {
		return fmt.Errorf("you are not allowed to make this request. Check the client or application entitlements")
	}

	if response.StatusCode == http.StatusBadRequest {
		var errorMessage VerifyError
		body, _ := io.ReadAll(response.Body)

		if err := json.Unmarshal(body, &errorMessage); err != nil {
			return fmt.Errorf("bad request: %s", defaultError)
		}
		// If the expected fields are not populated, return the raw response body.
		if errorMessage.MessageID == "" && errorMessage.MessageDescription == "" {
			body, _ := io.ReadAll(response.Body)
			return fmt.Errorf("bad request: %s", string(body))
		}
		return fmt.Errorf("%s %s", errorMessage.MessageID, errorMessage.MessageDescription)
	}

	if response.StatusCode == http.StatusNotFound {
		return fmt.Errorf("resource not found")
	}

	return nil
}
