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
	. "github.com/ibm-verify/verify-sdk-go/pkg/core/models"
)

type AttributeClient struct {
	Client *http.Client
}

type AttributesSearchCriteria struct {
	// Search is the criteria used to filter the attributes. The format to use the search query parameter is 'search={parameter}{operator}{value}
	//
	// The following search parameters are allowed: name, credname, tags, sourcetype, id, scope.
	// Valid operators for string values are =, !=, contains, startswith, endswith, and exists. Only for the 'exists' operator, there is no need to specify search value.
	// For all other operators, use double quotation marks for the search values.
	//
	// Multiple search conditions can be combined using either the & (AND) or | (OR) operators. Conditions in parentheses () have a higher priority and are evaluated first.
	// Without parentheses, & (AND) is evaluated first. Nested parentheses are not supported.
	//
	// Example:
	//  Search for attributes with 'sso' tag: tags="sso"
	//  Search for attributes with name that starts with 'pre': name startswith "pre"
	//  Search for attributes with tag: tags exists
	//  Search for attributes with the SSO tag with the name 'email' or name starts with 'mobile': tags="sso"&(name="email"|name startswith "mobile")
	Search string

	// Sort indicates how the results should be sorted.
	//
	// The following sort parameters are allowed: name, credname, tags, sourcetype, scope.
	// Each sort parameter must be prefixed with either + or -.
	//
	// Example:
	// 	Sort attributes by ascending 'name': sort=+name
	Sort string

	// Limit indicates the number of results returned.
	Limit int

	// Page indicates the page number. Usually, this is paired with limit.
	Page int
}

func NewAttributeClient() *AttributeClient {
	return &AttributeClient{}
}

func (c *AttributeClient) GetAttribute(ctx context.Context, id string) (*Attribute, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	params := GetAttribute0Params{
		Authorization: fmt.Sprintf("Bearer %s", vc.Token),
	}
	resp, err := client.GetAttribute0WithResponse(ctx, id, &params)
	if err != nil {
		vc.Logger.Errorf("unable to get the attribute; err=%s", err.Error())
		return nil, err
	}

	if e := resp.JSON400; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("bad request: err=%s", err.Error())
		return nil, err
	}

	if e := resp.JSON404; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("not found: err=%s", err.Error())
		return nil, err
	}

	if e := resp.JSON500; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("internal server error: err=%s", err.Error())
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		vc.Logger.Errorf("unable to get the attribute; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, errorsx.G11NError("unable to get the attribute")
	}

	attribute := &Attribute{}
	if err := json.Unmarshal(resp.Body, attribute); err != nil {
		vc.Logger.Errorf("unable to unmarshal the body; err=%v, body=%s", err, string(resp.Body))
		return nil, errorsx.G11NError("unable to get the attribute")
	}

	return attribute, nil
}

func (c *AttributeClient) GetAttributes(ctx context.Context, criteria *AttributesSearchCriteria) (*AttributeList, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	params := &GetAllAttributesParams{
		Authorization: fmt.Sprintf("Bearer %s", vc.Token),
	}

	hasCriteria := false
	pagination := url.Values{}
	if criteria != nil {
		if len(criteria.Search) > 0 {
			params.Search = criteria.Search
			hasCriteria = true
		}

		if len(criteria.Sort) > 0 {
			params.Sort = criteria.Sort
			hasCriteria = true
		}

		if criteria.Page > 0 {
			pagination.Set("page", fmt.Sprintf("%d", criteria.Page))
		}

		if criteria.Limit > 0 {
			pagination.Set("limit", fmt.Sprintf("%d", criteria.Limit))
		}

		if len(pagination) > 0 {
			params.Pagination = pagination.Encode()
			hasCriteria = true
		}
	}

	resp, err := client.GetAllAttributes(ctx, params)
	if err != nil {
		vc.Logger.Errorf("unable to get attributes; err=%v", err)
		return nil, err
	}

	buf, err := io.ReadAll(resp.Body)
	defer func() { _ = resp.Body.Close() }()
	if err != nil {
		vc.Logger.Errorf("unable to read the attributes body; err=%v", err)
		return nil, err
	}

	body := &AttributeList{}
	if len(pagination) > 0 {
		if err = json.Unmarshal(buf, &body); err != nil {
			vc.Logger.Errorf("unable to get the attributes; err=%s, body=%s", err, string(buf))
			return nil, errorsx.G11NError("unable to get the attributes")
		}
	} else {
		if err = json.Unmarshal(buf, &body.Attributes); err != nil {
			vc.Logger.Errorf("unable to get the attributes; err=%s, body=%s", err, string(buf))
			return nil, errorsx.G11NError("unable to get the attributes")
		}
	}

	return body, nil
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
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, resp.Body, "unable to create the attribute"); err != nil {
			vc.Logger.Errorf("unable to create the attribute; err=%s", err.Error())
			return "", err
		}

		vc.Logger.Errorf("unable to create the attribute; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", defaultErr
	}

	resourceURI := resp.HTTPResponse.Header.Get("Location")
	return resourceURI, nil
}

func (c *AttributeClient) UpdateAttribute(ctx context.Context, attribute *Attribute) error {
	vc := contextx.GetVerifyContext(ctx)
	defaultErr := errorsx.G11NError("unable to update attribute")
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	if len(attribute.ID) == 0 {
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
	resp, err := client.UpdateAttributeWithBodyWithResponse(ctx, attribute.ID, params, "application/json", bytes.NewReader(body))
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
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, resp.Body, "unable to update attribute"); err != nil {
			vc.Logger.Errorf("unable to update the attribute; err=%s", err.Error())
			return err
		}

		vc.Logger.Errorf("unable to update the attribute; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return defaultErr
	}

	return nil
}

func (c *AttributeClient) DeleteAttribute(ctx context.Context, id string) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	if id == "" {
		return errorsx.G11NError("'%s' is required", "id")
	}
	params := &openapi.DeleteAttributeParams{
		Authorization: fmt.Sprintf("Bearer %s", vc.Token),
	}
	resp, err := client.DeleteAttributeWithResponse(ctx, id, params)
	if err != nil {
		vc.Logger.Errorf("unable to delete attribute; err=%s", err.Error())
		return errorsx.G11NError("unable to delete attribute; err=%s", err.Error())
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
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, resp.Body, "unable to delete attribute"); err != nil {
			vc.Logger.Errorf("unable to delete attribute; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("unable to delete attribute; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("unable to delete attribute; code=%d", resp.StatusCode())
	}
	return nil
}
