package openapi

import (
	"context"
	"fmt"
	"net/http"

	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

func NewClientWithOptions(ctx context.Context, tenant string, c *http.Client) *ClientWithResponses {
	cwr, err := NewClientWithResponses(fmt.Sprintf("https://%s", tenant), func(oc *Client) error {
		if c != nil {
			oc.Client = c
		}

		return nil
	})

	if err != nil {
		// no point proceeding
		panic(err.Error())
	}

	return cwr
}

func DefaultRequestEditors(ctx context.Context, token string) []RequestEditorFn {
	return []RequestEditorFn{
		func(ctx context.Context, req *http.Request) error {
			if len(token) > 0 {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			}

			return nil
		},
	}
}

func (e *TemplateError) ConvertToError() *errorsx.VerifyError {
	return &errorsx.VerifyError{
		MessageID:          *e.MessageID,
		MessageDescription: *e.MessageDescription,
	}
}
