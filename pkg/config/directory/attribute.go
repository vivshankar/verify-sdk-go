package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

type AttributeClient struct {
	Client *http.Client
}

type Attribute = openapi.Attribute0
type AttributeList = openapi.PaginatedAttribute0

func NewAttributeClient() *AttributeClient {
	return &AttributeClient{}
}

func (c *AttributeClient) GetAttribute(ctx context.Context, id string) (*Attribute, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	params := openapi.GetAttribute0Params{
		Authorization: fmt.Sprintf("Bearer %s", vc.Token),
	}
	resp, err := client.GetAttribute0WithResponse(ctx, id, &params)
	if err != nil {
		vc.Logger.Errorf("unable to get the attribute; err=%s", err.Error())
		return nil, "", err
	}

	if e := resp.JSON400; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("bad request: err=%s", err.Error())
		return nil, "", err
	}

	if e := resp.JSON404; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("not found: err=%s", err.Error())
		return nil, "", err
	}

	if e := resp.JSON500; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("internal server error: err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		vc.Logger.Errorf("unable to get the attribute; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the attribute")
	}

	attribute := &Attribute{}
	if err := json.Unmarshal(resp.Body, attribute); err != nil {
		vc.Logger.Errorf("unable to unmarshal the body; err=%v, body=%s", err, string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the attribute")
	}

	return attribute, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *AttributeClient) GetAttributes(ctx context.Context, search string, sort string, page int, limit int) (*AttributeList, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	params := &openapi.GetAllAttributesParams{
		Authorization: fmt.Sprintf("Bearer %s", vc.Token),
	}
	if len(search) > 0 {
		params.Search = &search
	}
	if len(sort) > 0 {
		params.Sort = &sort
	}
	pagination := url.Values{}
	if page > 0 {
		pagination.Set("page", fmt.Sprintf("%d", page))
	}

	if limit > 0 {
		pagination.Set("limit", fmt.Sprintf("%d", limit))
	}
	paginationStr := pagination.Encode()
	if paginationStr != "" {
		params.Pagination = &paginationStr
	}

	resp, err := client.GetAllAttributes(ctx, params)
	if err != nil {
		vc.Logger.Errorf("unable to get attributes; err=%v", err)
		return nil, "", err
	}

	buf, err := io.ReadAll(resp.Body)
	defer func() { _ = resp.Body.Close() }()
	if err != nil {
		vc.Logger.Errorf("unable to read the attributes body; err=%v", err)
		return nil, "", err
	}

	body := &AttributeList{}
	if len(pagination) > 0 {
		if err = json.Unmarshal(buf, &body); err != nil {
			vc.Logger.Errorf("unable to get the attributes; err=%s, body=%s", err, string(buf))
			return nil, "", errorsx.G11NError("unable to get the attributes")
		}
	} else {
		if err = json.Unmarshal(buf, &body.Attributes); err != nil {
			vc.Logger.Errorf("unable to get the attributes; err=%s, body=%s", err, string(buf))
			return nil, "", errorsx.G11NError("unable to get the attributes")
		}
	}

	return body, resp.Request.URL.String(), nil
}

// CreateAttribute creates an attribute and returns the resource URI.
func (c *AttributeClient) CreateAttribute(ctx context.Context, attribute *Attribute) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	defaultErr := errorsx.G11NError("unable to create attribute")
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	params := &openapi.CreateAttributeParams{
		Authorization: fmt.Sprintf("Bearer %s", vc.Token),
	}

	// set some defaults
	if attribute.SchemaAttribute != nil && len(attribute.SchemaAttribute.AttributeName) == 0 && attribute.SchemaAttribute.CustomAttribute {
		attribute.SchemaAttribute.AttributeName = attribute.SchemaAttribute.ScimName
	}

	b, err := json.Marshal(attribute)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the attribute; err=%v", err)
		return "", defaultErr
	}
	resp, err := client.CreateAttributeWithBodyWithResponse(ctx, params, "application/json", bytes.NewReader(b))
	if err != nil {
		vc.Logger.Errorf("unable to create attribute; err=%v", err)
		return "", defaultErr
	}

	if e := resp.JSON400; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("bad request: err=%s", err.Error())
		return "", err
	}

	if e := resp.JSON500; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("internal server error: err=%s", err.Error())
		return "", err
	}

	if resp.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to create the attribute"); err != nil {
			vc.Logger.Errorf("unable to create the attribute; err=%s", err.Error())
			return "", err
		}

		vc.Logger.Errorf("unable to create the attribute; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", defaultErr
	}

	// unmarshal the response body to get the ID
	/*m := map[string]any{}
	resourceURI := ""
	if err := json.Unmarshal(resp.Body, &m); err != nil {
		vc.Logger.Warnf("unable to unmarshal the response body to get the 'id'")
		resourceURI = resp.HTTPResponse.Header.Get("Location")
	} else {
		id := typesx.Map(m).SafeString("id", "")
		resourceURI = resp.HTTPResponse.Request.URL.JoinPath(id).String()
	}*/
	resourceURI := resp.HTTPResponse.Header.Get("Location")
	return resourceURI, nil
}

func (c *AttributeClient) UpdateAttribute(ctx context.Context, attribute *Attribute) error {
	vc := contextx.GetVerifyContext(ctx)
	defaultErr := errorsx.G11NError("unable to update attribute")
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	if len(*attribute.ID) == 0 {
		return errorsx.G11NError("'%s' is required", "id")
	}
	params := &openapi.UpdateAttributeParams{
		Authorization: fmt.Sprintf("Bearer %s", vc.Token),
	}
	body, err := json.Marshal(attribute)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the attribute; err=%v", err)
		return defaultErr
	}
	resp, err := client.UpdateAttributeWithBodyWithResponse(ctx, *attribute.ID, params, "application/json", bytes.NewReader(body))
	if err != nil {
		vc.Logger.Errorf("unable to update attribute; err=%v", err)
		return defaultErr
	}

	if e := resp.JSON400; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("bad request: err=%s", err.Error())
		return err
	}

	if e := resp.JSON404; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("not found: err=%s", err.Error())
		return err
	}

	if e := resp.JSON500; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("internal server error: err=%s", err.Error())
		return err
	}

	if resp.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to update attribute"); err != nil {
			vc.Logger.Errorf("unable to update the attribute; err=%s", err.Error())
			return err
		}

		vc.Logger.Errorf("unable to update the attribute; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return defaultErr
	}

	return nil
}
