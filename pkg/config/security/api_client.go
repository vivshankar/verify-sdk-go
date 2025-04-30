package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

type APIClient struct {
	Client *http.Client
}

type APIClientListResponse = openapi.APIClientConfigPaginatedResponseContainer
type APIClientConfig = openapi.APIClientConfig

func NewAPIClient() *APIClient {
	return &APIClient{}
}

func (c *APIClient) CreateAPIClient(ctx context.Context, apiClientConfig *APIClientConfig) (string, error) {
	if apiClientConfig == nil {
		return "", errorsx.G11NError("client object is nil")
	}

	vc := contextx.GetVerifyContext(ctx)
	defaultErr := errorsx.G11NError("unable to create API client")
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	body, err := json.Marshal(apiClientConfig)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal API client data; err=%v", err)
		return "", defaultErr
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.CreateAPIClientWithBodyWithResponse(ctx, "application/json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("Unable to create API client; err=%v", err)
		return "", defaultErr
	}

	if response.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get API client"); err != nil {
			vc.Logger.Errorf("unable to create the API client; err=%s", err.Error())
			return "", err
		}

		vc.Logger.Errorf("unable to create the API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return "", defaultErr
	}

	// unmarshal the response body to get the ID
	resourceURI := ""
	resourceURI = response.HTTPResponse.Header.Get("Location")

	return resourceURI, nil
}

func (c *APIClient) GetAPIClientByName(ctx context.Context, clientName string) (*APIClientConfig, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	ID, err := c.getAPIClientId(ctx, clientName)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return nil, "", err
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.GetAPIClientWithResponse(ctx, ID, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the API client; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get API client"); err != nil {
			vc.Logger.Errorf("unable to get the API client; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return nil, "", errorsx.G11NError("unable to get the API client with clientName %s; status=%d", clientName, response.StatusCode())
	}

	APIClient := &APIClientConfig{}
	if err = json.Unmarshal(response.Body, APIClient); err != nil {
		return nil, "", errorsx.G11NError("unable to get the API client")
	}

	return APIClient, response.HTTPResponse.Request.URL.String(), nil
}

func (c *APIClient) GetAPIClientByID(ctx context.Context, clientID string) (*APIClientConfig, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.GetAPIClientWithResponse(ctx, clientID, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the API client; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get API client"); err != nil {
			vc.Logger.Errorf("unable to get the API client; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return nil, "", errorsx.G11NError("unable to get the API client with clientID %s; status=%d", clientID, response.StatusCode())
	}

	APIClient := &APIClientConfig{}
	if err = json.Unmarshal(response.Body, APIClient); err != nil {
		return nil, "", errorsx.G11NError("unable to get the API client")
	}

	return APIClient, response.HTTPResponse.Request.URL.String(), nil
}

func (c *APIClient) GetAPIClients(ctx context.Context, search string, sort string, page int, limit int) (*APIClientListResponse, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	params := &openapi.GetAPIClientsParams{}
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

	if len(pagination) > 0 {
		paginationStr := pagination.Encode()
		params.Pagination = &paginationStr
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.GetAPIClientsWithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)

	if err != nil {
		vc.Logger.Errorf("unable to get the API clients; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get API clients"); err != nil {
			vc.Logger.Errorf("unable to get the API clients; err=%s", err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the API clients; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return nil, "", errorsx.G11NError("unable to get the API clients")
	}

	apiclientsResponse := &APIClientListResponse{}
	if err = json.Unmarshal(response.Body, &apiclientsResponse); err != nil {
		vc.Logger.Errorf("unable to get the API clients; err=%s, body=%s", err, string(response.Body))
		return nil, "", errorsx.G11NError("unable to get the API clients")
	}

	return apiclientsResponse, response.HTTPResponse.Request.URL.String(), nil
}

func (c *APIClient) UpdateAPIClient(ctx context.Context, apiClientConfig *APIClientConfig) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	if apiClientConfig == nil {
		vc.Logger.Errorf("client object is nil")
		return errorsx.G11NError("client object is nil")
	}

	ID, err := c.getAPIClientId(ctx, apiClientConfig.ClientName)
	if err != nil {
		vc.Logger.Errorf("unable to get the client ID for API client '%s'; err=%s", apiClientConfig.ClientName, err.Error())
		return errorsx.G11NError("unable to get the client ID for API client '%s'; err=%s", apiClientConfig.ClientName, err.Error())
	}
	apiClientConfig.ID = &ID
	body, err := json.Marshal(apiClientConfig)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the API client; err=%v", err)
		return errorsx.G11NError("unable to marshal the API client; err=%v", err)
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.UpdateAPIClientWithBodyWithResponse(ctx, ID, "application/json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to update API client"); err != nil {
			vc.Logger.Errorf("unable to update the API client; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("unable to update API client; err=%v", err)
		return errorsx.G11NError("unable to update API client; err=%v", err)
	}
	if response.StatusCode() != http.StatusNoContent {
		vc.Logger.Errorf("failed to update API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return errorsx.G11NError("failed to update API client ; code=%d, body=%s", response.StatusCode(), string(response.Body))
	}

	return nil

}

func (c *APIClient) DeleteAPIClientById(ctx context.Context, ID string) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.DeleteAPIClientWithResponse(ctx, ID, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete API client; err=%s", err.Error())
		return errorsx.G11NError("unable to delete the API client; err=%s", err.Error())
	}
	if response.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to delete API client"); err != nil {
			vc.Logger.Errorf("unable to delete the API client; err=%s", err.Error())
			return errorsx.G11NError("unable to delete the API client; err=%s", err.Error())
		}
		vc.Logger.Errorf("unable to delete the API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return errorsx.G11NError("unable to delete the API client; code=%d, body=%s", response.StatusCode(), string(response.Body))
	}
	return nil
}

func (c *APIClient) getAPIClientId(ctx context.Context, clientName string) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	search := fmt.Sprintf(`clientName contains "%s"`, clientName)
	params := &openapi.GetAPIClientsParams{
		Search: &search,
	}

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	response, err := client.GetAPIClientsWithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, headers)...)

	if err != nil {
		vc.Logger.Errorf("unable to query API clients; err=%s", err.Error())
		return "", err
	}

	if response.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to get API client"); err != nil {
			vc.Logger.Errorf("unable to get the API client with clientName %s; err=%s", clientName, err.Error())
			return "", errorsx.G11NError("unable to get the API client with clientName %s; err=%s", clientName, err.Error())
		}

		vc.Logger.Errorf("unable to get API client ID; code=%d, body=%s", response.StatusCode(), string(response.Body))
		return "", errorsx.G11NError("unable to get API client ID with clientName %s; status=%d", clientName, response.StatusCode())

	}

	var data map[string]interface{}
	if err := json.Unmarshal(response.Body, &data); err != nil {
		vc.Logger.Errorf("failed to parse API response; err=%s", err.Error())
		return "", errorsx.G11NError("failed to parse API response: %w", err)
	}

	apiClients, ok := data["apiClients"].([]interface{})
	if !ok || len(apiClients) == 0 {
		vc.Logger.Infof("no API client found with clientName %s", clientName)
		return "", errorsx.G11NError("no API client found with clientName %s", clientName)
	}

	for _, resource := range apiClients {
		client, ok := resource.(map[string]interface{})
		if !ok {
			vc.Logger.Errorf("invalid client format in API response")
			return "", errorsx.G11NError("invalid client format in API response")
		}

		name, ok := client["clientName"].(string)
		if !ok {
			vc.Logger.Errorf("clientName not found or invalid type in API response")
			return "", errorsx.G11NError("clientName not found or invalid type in API response")
		}

		if name == clientName {
			ID, ok := client["id"].(string)
			if !ok {
				vc.Logger.Errorf("ID not found or invalid type in API response")
				return "", errorsx.G11NError("ID not found or invalid type in API response")
			}
			vc.Logger.Debugf("Resolved clientName %s to ID %s", clientName, ID)
			return ID, nil
		}
	}

	vc.Logger.Infof("no exact match found for clientName %s", clientName)
	return "", errorsx.G11NError("no API client found with exact clientName %s", clientName)
}
