package openapi

import (
	"context"
	"fmt"
	"net/http"

	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

type Headers struct {
	Token       string
	Accept      string
	ContentType string
}

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

func DefaultRequestEditors(ctx context.Context, headers *Headers) []RequestEditorFn {
	return []RequestEditorFn{
		func(ctx context.Context, req *http.Request) error {
			if len(headers.Token) > 0 {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", headers.Token))
			}
			if len(headers.Accept) > 0 {
				req.Header.Set("Accept", headers.Accept)
			}
			if len(headers.ContentType) > 0 {
				req.Header.Set("Content-Type", headers.ContentType)
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

func (e *ErrorBean) ConvertToError() *errorsx.VerifyError {
	return &errorsx.VerifyError{
		MessageID:          e.MessageID,
		MessageDescription: e.MessageDescription,
	}
}
