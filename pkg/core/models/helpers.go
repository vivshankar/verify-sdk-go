package models

import (
	"encoding/json"
	"fmt"

	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

func (e *TemplateError) ConvertToError() *errorsx.VerifyError {
	return &errorsx.VerifyError{
		MessageID:          e.MessageID,
		MessageDescription: e.MessageDescription,
	}
}

func (e *ErrorBean) ConvertToError() *errorsx.VerifyError {
	return &errorsx.VerifyError{
		MessageID:          e.MessageID,
		MessageDescription: e.MessageDescription,
	}
}

type StringOrBoolean bool

func (o *StringOrBoolean) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err != nil {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("failed to unmarshal boolean: %w", err)
		}

		b = "true" == s
	}

	*o = StringOrBoolean(b)
	return nil
}

type ApplicationOwner string

func (o *ApplicationOwner) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, o); err == nil {
		return nil
	}

	bean := &OwnerBean{}
	err := json.Unmarshal(data, bean)
	if err != nil {
		return err
	}

	*o = ApplicationOwner(bean.ID)
	return nil
}
