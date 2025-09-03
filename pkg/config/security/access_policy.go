package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

// Root structure
type PolicyListResponse struct {
	Total    int       `json:"total" yaml:"total"`
	Count    int       `json:"count" yaml:"count"`
	Limit    int       `json:"limit" yaml:"limit"`
	Page     int       `json:"page" yaml:"page"`
	Policies []*Policy `json:"policies" yaml:"policies"`
}

// Policy structure
type Policy struct {
	ID                    int              `json:"id,omitempty" yaml:"id,omitempty"`
	Name                  string           `json:"name" yaml:"name"`
	Description           string           `json:"description" yaml:"description"`
	Rules                 []*Rule          `json:"rules" yaml:"rules"`
	Meta                  AccessPolicyMeta `json:"meta" yaml:"meta"`
	Validations           Validations      `json:"validations" yaml:"validations"`
	RequiredSubscriptions []string         `json:"requiredSubscription,omitempty" yaml:"requiredSubscriptions,omitempty"`
}

// Rule structure
type Rule struct {
	ID          string       `json:"id,omitempty" yaml:"id,omitempty"`
	Name        string       `json:"name,omitempty" yaml:"name,omitempty"`
	Description string       `json:"description,omitempty" yaml:"description,omitempty"`
	AlwaysRun   bool         `json:"alwaysRun" yaml:"alwaysRun"`
	FirstFactor bool         `json:"firstFactor" yaml:"firstFactor"`
	Conditions  []*Condition `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	Result      Result       `json:"result,omitempty" yaml:"result,omitempty"`
}

// Condition represents a policy condition
type Condition struct {
	Type       string        `json:"type" yaml:"type"`
	Values     []string      `json:"values,omitempty" yaml:"values,omitempty"`
	Enabled    *bool         `json:"enabled,omitempty" yaml:"enabled,omitempty"`       // Nullable boolean
	Opcode     *string       `json:"opCode,omitempty" yaml:"opCode,omitempty"`         // Nullable string
	Attributes []*Attributes `json:"attributes,omitempty" yaml:"attributes,omitempty"` // Nested attributes
}

// Attribute represents an attribute within a condition
type Attributes struct {
	Name   string   `json:"name" yaml:"name"`
	Opcode string   `json:"opCode" yaml:"opCode"`
	Values []string `json:"values,omitempty" yaml:"values,omitempty"`
}

// Result structure
type Result struct {
	Action            string              `json:"action" yaml:"action"`
	ServerSideActions []*ServerSideAction `json:"serverSideActions" yaml:"serverSideActions"`
	AuthnMethods      []string            `json:"authnMethods" yaml:"authnMethods"`
}

// ServerSideAction structure
type ServerSideAction struct {
	ActionID string `json:"actionId" yaml:"actionId"`
	Version  string `json:"version" yaml:"version"`
}

// Meta structure
type AccessPolicyMeta struct {
	State               string   `json:"state,omitempty" yaml:"state,omitempty"`
	Schema              string   `json:"schema,omitempty" yaml:"schema,omitempty"`
	Revision            int      `json:"revision,omitempty" yaml:"revision,omitempty"`
	Label               string   `json:"label,omitempty" yaml:"label,omitempty"`
	Predefined          bool     `json:"predefined" yaml:"predefined"`
	Created             int64    `json:"created,omitempty" yaml:"created,omitempty"`
	CreatedBy           string   `json:"createdBy,omitempty" yaml:"createdBy,omitempty"`
	LastActive          int64    `json:"lastActive,omitempty" yaml:"lastActive,omitempty"`
	Modified            int64    `json:"modified,omitempty" yaml:"modified,omitempty"`
	ModifiedBy          string   `json:"modifiedBy,omitempty" yaml:"modifiedBy,omitempty"`
	Scope               []string `json:"scope,omitempty" yaml:"scope,omitempty"`
	EnforcementType     string   `json:"enforcementType,omitempty" yaml:"enforcementType,omitempty"`
	ReferencedBy        []string `json:"referencedBy,omitempty" yaml:"referencedBy,omitempty"`
	References          []string `json:"references,omitempty" yaml:"references,omitempty"`
	TenantDefaultPolicy bool     `json:"tenantDefaultPolicy" yaml:"tenantDefaultPolicy"`
}

// Validations structure
type Validations struct {
	SubscriptionsNeeded []string `json:"subscriptionsNeeded" yaml:"subscriptionsNeeded"`
}

type PolicyClient struct {
	Client *http.Client
}

func NewAccessPolicyClient() *PolicyClient {
	return &PolicyClient{}
}

func (c *PolicyClient) CreateAccessPolicy(ctx context.Context, accessPolicy *Policy) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	defaultErr := fmt.Errorf("unable to create accessPolicy")

	b, err := json.Marshal(accessPolicy)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal accessPolicy data; err=%v", err)
		return "", defaultErr
	}
	headers := &openapi.Headers{
		Accept: "application/json",
		Token:  vc.Token,
	}
	response, err := client.CreateAccessPolicyWithBodyWithResponse(ctx, "application/json", bytes.NewBuffer(b), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("Unable to create accessPolicy; err=%v", err)
		return "", defaultErr
	}

	if response.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to create accessPolicy"); err != nil {
			vc.Logger.Errorf("unable to create the accessPolicy; err=%s", err.Error())
			return "", fmt.Errorf("unable to create the accessPolicy; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to create the accessPolicy; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return "", fmt.Errorf("unable to create the accessPolicy; code=%d, body=%s", response.StatusCode(), string(response.Body))
	}

	m := map[string]any{}
	if err := json.Unmarshal(response.Body, &m); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	id, ok := m["id"].(float64)
	if !ok {
		return "", fmt.Errorf("failed to parse 'id' as float64")
	}

	return fmt.Sprintf("%s/%d", response.HTTPResponse.Request.URL.String(), int(id)), nil
}

func (c *PolicyClient) GetAccessPolicy(ctx context.Context, policyID string) (*Policy, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	id, err := strconv.Atoi(policyID)
	if err != nil {
		vc.Logger.Errorf("unable to get the access policy ID; err=%s", err.Error())
		return nil, "", err
	}
	headers := &openapi.Headers{
		Accept: "application/json",
		Token:  vc.Token,
	}
	response, err := client.GetAccessPolicyWithResponse(ctx, int64(id), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the Access Policy; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get Access Policy"); err != nil {
			vc.Logger.Errorf("unable to get the Access Policy; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Access Policy; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return nil, "", fmt.Errorf("unable to get the Access Policy")
	}

	AccessPolicy := &Policy{}
	if err = json.Unmarshal(response.Body, AccessPolicy); err != nil {
		return nil, "", fmt.Errorf("unable to get the Access Policy")
	}

	return AccessPolicy, response.HTTPResponse.Request.URL.String(), nil
}

func (c *PolicyClient) GetAccessPolicies(ctx context.Context, page int, limit int) (*PolicyListResponse, string, error) {

	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	params := &openapi.ListAccessPoliciesParams{}
	pagination := url.Values{}
	if page > 0 {
		pagination.Set("page", fmt.Sprintf("%d", page))
	}

	if limit > 0 {
		pagination.Set("limit", fmt.Sprintf("%d", limit))
	}

	if len(pagination) > 0 {
		paginationStr := pagination.Encode()
		params.Pagination = &paginationStr
	}
	headers := &openapi.Headers{
		Accept: "application/json",
		Token:  vc.Token,
	}
	response, err := client.ListAccessPoliciesWithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)

	if err != nil {
		vc.Logger.Errorf("unable to get the Access Policies; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get Access Policies"); err != nil {
			vc.Logger.Errorf("unable to get the Access Policies; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Access Policies; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return nil, "", fmt.Errorf("unable to get the Access Policies")
	}

	AccessPoliciesResponse := &PolicyListResponse{}
	if err = json.Unmarshal(response.Body, &AccessPoliciesResponse); err != nil {
		vc.Logger.Errorf("unable to get the AccessPolicies; err=%s, body=%s", err, string(response.Body))
		return nil, "", fmt.Errorf("unable to get the AccessPolicies")
	}

	return AccessPoliciesResponse, response.HTTPResponse.Request.URL.String(), nil
}

func (c *PolicyClient) DeleteAccessPolicyByID(ctx context.Context, policyID string) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	ID, err := strconv.Atoi(policyID)
	if err != nil {
		vc.Logger.Errorf("unable to get the access policy ID; err=%s", err.Error())
		return err
	}
	headers := &openapi.Headers{
		Accept: "application/json",
		Token:  vc.Token,
	}
	response, err := client.DeleteAccessPolicyWithResponse(ctx, int64(ID), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete the Access Policy; err=%s", err.Error())
		return fmt.Errorf("unable to delete the Access Policy; err=%s", err.Error())
	}

	if response.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to delete Access Policy"); err != nil {
			vc.Logger.Errorf("unable to delete the Access Policy; err=%s", err.Error())
			return fmt.Errorf("unable to delete the Access Policy; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to delete the Access Policy; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return fmt.Errorf("unable to delete the Access Policy; code=%d, body=%s", response.StatusCode(), string(response.Body))
	}

	return nil
}

func (c *PolicyClient) UpdateAccessPolicy(ctx context.Context, accessPolicy *Policy) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Accept:      "application/json",
		ContentType: "application/json",
		Token:       vc.Token,
	}

	b, err := json.Marshal(accessPolicy)

	if err != nil {
		vc.Logger.Errorf("unable to marshal the patch request; err=%v", err)
		return fmt.Errorf("unable to marshal the patch request; err=%v", err)
	}

	response, err := client.UpdateAccessPolicyWithBodyWithResponse(ctx, int64(accessPolicy.ID), "", bytes.NewBuffer(b), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to update accessPolicy; err=%v", err)
		return fmt.Errorf("unable to update accessPolicy; err=%v", err)
	}
	if response.StatusCode() != http.StatusCreated {
		vc.Logger.Errorf("failed to update accessPolicy; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return fmt.Errorf("failed to update accessPolicy ; code=%d, body=%s", response.StatusCode(), string(response.Body))
	}

	return nil
}

func (c *PolicyClient) GetAccessPolicyID(ctx context.Context, name string) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	search := fmt.Sprintf(`name = "%s"`, name)
	params := &openapi.ListAccessPoliciesParams{
		Search: &search,
	}
	headers := &openapi.Headers{
		Accept: "application/json",
		Token:  vc.Token,
	}
	response, _ := client.ListAccessPoliciesWithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get Access Policy"); err != nil {
			vc.Logger.Errorf("unable to get the Access Policy with accessPolicyName %s; err=%s", name, err.Error())
			return "", fmt.Errorf("unable to get the Access Policy with accessPolicyName %s; err=%s", name, err.Error())
		}
	}

	var data map[string]any
	if err := json.Unmarshal(response.Body, &data); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	policies, ok := data["policies"].([]any)
	if !ok || len(policies) == 0 {
		return "", fmt.Errorf("no accessPolicy found with accessPolicyName %s", name)
	}

	firstResource, ok := policies[0].(map[string]any)
	if !ok {
		return "", fmt.Errorf("invalid resource format")
	}

	// Extract "id" field
	id, ok := firstResource["id"].(float64)
	if !ok {
		return "", fmt.Errorf("ID not found or invalid type")
	}
	return fmt.Sprintf("%d", int(id)), nil
}

func AccessPolicyExample() *Policy {
	var accessPolicy *Policy = &Policy{}
	// add rule
	accessPolicy.Rules = []*Rule{
		{
			AlwaysRun:   false,
			FirstFactor: false,
			Result: Result{
				Action:       " ",
				AuthnMethods: []string{" "},
			},
		},
	}
	// add meta
	accessPolicy.Meta = AccessPolicyMeta{
		State:               " ",
		Schema:              "urn:access:policy:5.0:schema",
		Revision:            1,
		Label:               " ",
		Predefined:          false,
		Scope:               []string{" "},
		EnforcementType:     "",
		TenantDefaultPolicy: false,
	}
	return accessPolicy
}
