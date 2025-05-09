package integrations

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

type IdentityAgents struct {
	Client *http.Client
}

type IdentityAgentListResponse = []openapi.OnpremAgentConfiguration

type IdentityAgentConfig = openapi.OnpremAgentConfiguration

func NewIdentityAgents() *IdentityAgents {
	return &IdentityAgents{}
}

func (c *IdentityAgents) CreateIdentityAgent(ctx context.Context, IdentityAgentConfig *IdentityAgentConfig) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	defaultErr := errorsx.G11NError("unable to create Identity Agent")
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	body, err := json.Marshal(IdentityAgentConfig)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal Identity Agent data; err=%v", err)
		return "", defaultErr
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.CreateOnpremAgentWithBodyWithResponse(ctx, "application/json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("Unable to create Identity Agent; err=%v", err)
		return "", defaultErr
	}

	if response.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get Identity Agent"); err != nil {
			vc.Logger.Errorf("unable to create the Identity Agent; err=%s", err.Error())
			return "", err
		}

		vc.Logger.Errorf("unable to create the Identity Agent; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return "", defaultErr
	}

	// unmarshal the response body to get the ID
	resourceURI := ""
	resourceURI = response.HTTPResponse.Header.Get("Location")

	return resourceURI, nil
}

// func (c *IdentityAgents) GetIdentityAgentsByName(ctx context.Context, clientName string) (*IdentityAgentsConfig, string, error) {
// 	vc := contextx.GetVerifyContext(ctx)
// 	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
// 	ID, err := c.getIdentityAgentsId(ctx, clientName)
// 	if err != nil {
// 		vc.Logger.Errorf("unable to get the api client ID; err=%s", err.Error())
// 		return nil, "", err
// 	}

// 	headers := &openapi.Headers{
// 		Token:  vc.Token,
// 		Accept: "application/json",
// 	}
// 	response, err := client.GetIdentityAgentsWithResponse(ctx, ID, openapi.DefaultRequestEditors(ctx, headers)...)
// 	if err != nil {
// 		vc.Logger.Errorf("unable to get the API client; err=%s", err.Error())
// 		return nil, "", err
// 	}

// 	if response.StatusCode() != http.StatusOK {
// 		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get API client"); err != nil {
// 			vc.Logger.Errorf("unable to get the API client; err=%s", err.Error())
// 			return nil, "", err
// 		}

// 		vc.Logger.Errorf("unable to get the API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
// 		return nil, "", errorsx.G11NError("unable to get the API client with clientName %s; status=%d", clientName, response.StatusCode())
// 	}

// 	IdentityAgents := &IdentityAgentsConfig{}
// 	if err = json.Unmarshal(response.Body, IdentityAgents); err != nil {
// 		return nil, "", errorsx.G11NError("unable to get the API client")
// 	}

// 	return IdentityAgents, response.HTTPResponse.Request.URL.String(), nil
// }

func (c *IdentityAgents) GetIdentityAgentByID(ctx context.Context, identityAgentID string) (*IdentityAgentConfig, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.GetOnpremAgentWithResponse(ctx, identityAgentID, &openapi.GetOnpremAgentParams{}, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the Identity agent; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get Identity agent"); err != nil {
			vc.Logger.Errorf("unable to get the Identity agent; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the Identity agent; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return nil, "", errorsx.G11NError("unable to get the Identity agent with identityAgentID %s; status=%d", identityAgentID, response.StatusCode())
	}

	identityAgent := &IdentityAgentConfig{}
	if err = json.Unmarshal(response.Body, identityAgent); err != nil {
		return nil, "", errorsx.G11NError("unable to get the Identity agent")
	}

	return identityAgent, response.HTTPResponse.Request.URL.String(), nil
}

func (c *IdentityAgents) GetIdentityAgents(ctx context.Context, search string, page int, limit int) (*IdentityAgentListResponse, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	params := &openapi.ListOnpremAgentsParams{}
	if len(search) > 0 {
		params.Search = &search
	}

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
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.ListOnpremAgents(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the Identity agents; err=%s", err.Error())
		return nil, "", err
	}
	defer func() { _ = response.Body.Close() }()

	buf, err := io.ReadAll(response.Body)

	if err != nil {
		vc.Logger.Errorf("unable to get the Identity agents; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode != http.StatusOK {
		fmt.Println(response.StatusCode)
		if err := errorsx.HandleCommonErrors(ctx, response, "unable to get Identity agents"); err != nil {
			vc.Logger.Errorf("unable to get the Identity agents; err=%s", err.Error())
			return nil, "", err
		}
		data, _ := io.ReadAll(response.Body)
		vc.Logger.Errorf("unable to get the Identity agents; code=%d, body=%s", response.StatusCode, string(data))
		return nil, "", errorsx.G11NError("unable to get the Identity agents")
	}

	identityAgentResponse := &IdentityAgentListResponse{}
	if err = json.Unmarshal(buf, &identityAgentResponse); err != nil {
		vc.Logger.Errorf("unable to get the Identity agents; err=%s, body=%s", err)
		return nil, "", errorsx.G11NError("unable to get the Identity agents")
	}

	return identityAgentResponse, response.Request.URL.String(), nil
}

// func (c *IdentityAgents) UpdateIdentityAgents(ctx context.Context, IdentityAgentsConfig *IdentityAgentsConfig) error {
// 	vc := contextx.GetVerifyContext(ctx)
// 	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
// 	if IdentityAgentsConfig == nil {
// 		vc.Logger.Errorf("client object is nil")
// 		return errorsx.G11NError("client object is nil")
// 	}

// 	ID, err := c.getIdentityAgentsId(ctx, IdentityAgentsConfig.ClientName)
// 	if err != nil {
// 		vc.Logger.Errorf("unable to get the client ID for API client '%s'; err=%s", IdentityAgentsConfig.ClientName, err.Error())
// 		return errorsx.G11NError("unable to get the client ID for API client '%s'; err=%s", IdentityAgentsConfig.ClientName, err.Error())
// 	}
// 	IdentityAgentsConfig.ID = &ID
// 	body, err := json.Marshal(IdentityAgentsConfig)
// 	if err != nil {
// 		vc.Logger.Errorf("unable to marshal the API client; err=%v", err)
// 		return errorsx.G11NError("unable to marshal the API client; err=%v", err)
// 	}

// 	headers := &openapi.Headers{
// 		Token:  vc.Token,
// 		Accept: "application/json",
// 	}
// 	response, err := client.UpdateIdentityAgentsWithBodyWithResponse(ctx, ID, "application/json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
// 	if err != nil {
// 		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to update API client"); err != nil {
// 			vc.Logger.Errorf("unable to update the API client; err=%s", err.Error())
// 			return err
// 		}
// 		vc.Logger.Errorf("unable to update API client; err=%v", err)
// 		return errorsx.G11NError("unable to update API client; err=%v", err)
// 	}
// 	if response.StatusCode() != http.StatusNoContent {
// 		vc.Logger.Errorf("failed to update API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
// 		return errorsx.G11NError("failed to update API client ; code=%d, body=%s", response.StatusCode(), string(response.Body))
// 	}

// 	return nil

// }

// func (c *IdentityAgents) DeleteIdentityAgentsByName(ctx context.Context, clientName string) error {
// 	vc := contextx.GetVerifyContext(ctx)
// 	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
// 	ID, err := c.getIdentityAgentsId(ctx, clientName)
// 	if err != nil {
// 		vc.Logger.Errorf("unable to get the api client ID; err=%s", err.Error())
// 		return err
// 	}
// 	headers := &openapi.Headers{
// 		Token:  vc.Token,
// 		Accept: "application/json",
// 	}
// 	response, err := client.DeleteIdentityAgentsWithResponse(ctx, ID, openapi.DefaultRequestEditors(ctx, headers)...)
// 	if err != nil {
// 		vc.Logger.Errorf("unable to delete API client; err=%s", err.Error())
// 		return errorsx.G11NError("unable to delete the API client; err=%s", err.Error())
// 	}
// 	if response.StatusCode() != http.StatusNoContent {
// 		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to delete API client"); err != nil {
// 			vc.Logger.Errorf("unable to delete the API client; err=%s", err.Error())
// 			return errorsx.G11NError("unable to delete the API client; err=%s", err.Error())
// 		}
// 		vc.Logger.Errorf("unable to delete the API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
// 		return errorsx.G11NError("unable to delete the API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
// 	}
// 	return nil
// }

func (c *IdentityAgents) DeleteIdentityAgentsById(ctx context.Context, identityAgentID string) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.DeleteOnpremAgentWithResponse(ctx, identityAgentID, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete Identity Agent; err=%s", err.Error())
		return errorsx.G11NError("unable to delete the Identity Agent; err=%s", err.Error())
	}
	if response.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to delete API client"); err != nil {
			vc.Logger.Errorf("unable to delete the Identity Agent; err=%s", err.Error())
			return errorsx.G11NError("unable to delete the Identity Agent; err=%s", err.Error())
		}
		vc.Logger.Errorf("unable to delete the Identity Agent; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return errorsx.G11NError("unable to delete the Identity Agent; code=%d, body=%s", response.StatusCode(), string(response.Body))
	}
	return nil
}

// func (c *IdentityAgents) getIdentityAgentsId(ctx context.Context, clientName string) (string, error) {
// 	vc := contextx.GetVerifyContext(ctx)
// 	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

// 	search := fmt.Sprintf(`clientName contains "%s"`, clientName)
// 	params := &openapi.GetIdentityAgentssParams{
// 		Search: &search,
// 	}

// 	headers := &openapi.Headers{
// 		Token:  vc.Token,
// 		Accept: "application/json",
// 	}
// 	response, err := client.GetIdentityAgentssWithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)

// 	if err != nil {
// 		vc.Logger.Errorf("unable to query API clients; err=%s", err.Error())
// 		return "", err
// 	}

// 	if response.StatusCode() != http.StatusOK {
// 		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get API client"); err != nil {
// 			vc.Logger.Errorf("unable to get the API client with clientName %s; err=%s", clientName, err.Error())
// 			return "", errorsx.G11NError("unable to get the API client with clientName %s; err=%s", clientName, err.Error())
// 		}

// 		vc.Logger.Errorf("unable to get API client ID; code=%d, body=%s", response.StatusCode(), string(response.Body))
// 		return "", errorsx.G11NError("unable to get API client ID with clientName %s; status=%d", clientName, response.StatusCode())

// 	}

// 	var data map[string]interface{}
// 	if err := json.Unmarshal(response.Body, &data); err != nil {
// 		vc.Logger.Errorf("failed to parse API response; err=%s", err.Error())
// 		return "", errorsx.G11NError("failed to parse API response: %w", err)
// 	}

// 	IdentityAgentss, ok := data["IdentityAgentss"].([]interface{})
// 	if !ok || len(IdentityAgentss) == 0 {
// 		vc.Logger.Infof("no API client found with clientName %s", clientName)
// 		return "", errorsx.G11NError("no API client found with clientName %s", clientName)
// 	}

// 	for _, resource := range IdentityAgentss {
// 		client, ok := resource.(map[string]interface{})
// 		if !ok {
// 			vc.Logger.Errorf("invalid client format in API response")
// 			return "", errorsx.G11NError("invalid client format in API response")
// 		}

// 		name, ok := client["clientName"].(string)
// 		if !ok {
// 			vc.Logger.Errorf("clientName not found or invalid type in API response")
// 			return "", errorsx.G11NError("clientName not found or invalid type in API response")
// 		}

// 		if name == clientName {
// 			ID, ok := client["id"].(string)
// 			if !ok {
// 				vc.Logger.Errorf("ID not found or invalid type in API response")
// 				return "", errorsx.G11NError("ID not found or invalid type in API response")
// 			}
// 			vc.Logger.Debugf("Resolved clientName %s to ID %s", clientName, ID)
// 			return ID, nil
// 		}
// 	}

// 	vc.Logger.Infof("no exact match found for clientName %s", clientName)
// 	return "", errorsx.G11NError("no API client found with exact clientName %s", clientName)
// }
