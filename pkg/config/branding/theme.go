package branding

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	httpx "github.com/ibm-verify/verify-sdk-go/pkg/core/http"
	typesx "github.com/ibm-verify/verify-sdk-go/x/types"
)

type Theme struct {
	ThemeID     string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
}

type ListThemesResponse struct {
	Count  int      `json:"count" yaml:"count"`
	Limit  int      `json:"limit" yaml:"limit"`
	Page   int      `json:"page" yaml:"page"`
	Total  int      `json:"total" yaml:"total"`
	Themes []*Theme `json:"themeRegistrations" yaml:"themeRegistrations"`
}

func NewThemeWithMap(m map[string]interface{}) *Theme {
	tm := typesx.Map(m)
	return &Theme{
		ThemeID:     tm.SafeString("id", ""),
		Name:        tm.SafeString("name", ""),
		Description: tm.SafeString("description", ""),
	}
}

func NewListThemesResponse(r *openapi.ThemeRegistrationPaginatedResponseContainer) *ListThemesResponse {
	ltr := &ListThemesResponse{}
	if r.Count != nil {
		ltr.Count = int(*r.Count)
	}

	if r.Limit != nil {
		ltr.Limit = int(*r.Limit)
	}

	if r.Page != nil {
		ltr.Page = int(*r.Page)
	}

	if r.Total != nil {
		ltr.Total = int(*r.Total)
	}

	if r.ThemeRegistrations == nil {
		return ltr
	}

	for _, tr := range *r.ThemeRegistrations {
		ltr.Themes = append(ltr.Themes, NewThemeWithMap(tr))
	}

	return ltr
}

type ThemeClient struct {
	httpClient *http.Client
}

func NewThemeClient() *ThemeClient {
	return &ThemeClient{}
}

func (c *ThemeClient) ListThemes(ctx context.Context, count int, page int, limit int) (*ListThemesResponse, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.httpClient)

	pagination := url.Values{}
	if count > 0 {
		pagination.Add("count", fmt.Sprintf("%d", count))
	}

	if page > 0 {
		pagination.Add("page", fmt.Sprintf("%d", page))
	}

	if limit > 0 {
		pagination.Add("limit", fmt.Sprintf("%d", limit))
	}

	params := &openapi.GetThemeRegistrationsParams{}
	if len(pagination) > 0 {
		paginationString := pagination.Encode()
		params.Pagination = &paginationString
	}

	resp, err := client.GetThemeRegistrationsWithResponse(ctx, params, openapi.DefaultRequestEditors(ctx, vc.Token)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the themes; err=%s", err.Error())
		return nil, "", err
	}

	if e := resp.JSON400; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("bad request: err=%s", err.Error())
		return nil, "", err
	}

	if e := resp.JSON401; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("unauthorized: err=%s", err.Error())
		return nil, "", err
	}

	if e := resp.JSON403; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("forbidden: err=%s", err.Error())
		return nil, "", err
	}

	if e := resp.JSON404; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("not found: err=%s", err.Error())
		return nil, "", err
	}

	if e := resp.JSON405; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("method not allowed: err=%s", err.Error())
		return nil, "", err
	}

	if e := resp.JSON406; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("not acceptable: err=%s", err.Error())
		return nil, "", err
	}

	if e := resp.JSON415; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("unsupported media type: err=%s", err.Error())
		return nil, "", err
	}

	if e := resp.JSON500; e != nil {
		err := e.ConvertToError()
		vc.Logger.Errorf("internal server error: err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		// something fell through the cracks
		vc.Logger.Errorf("responseCode=%d, responseBody=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the themes")
	}

	return NewListThemesResponse(resp.JSON200), resp.HTTPResponse.Request.URL.String(), nil
}

func (c *ThemeClient) GetTheme(ctx context.Context, themeID string, customizedOnly bool) ([]byte, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.httpClient)

	params := &openapi.DownloadThemeTemplatesParams{}
	params.CustomizedOnly = &customizedOnly
	resp, err := client.DownloadThemeTemplatesWithResponse(ctx, themeID, params, func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", vc.Token))
		req.Header.Set("Accept", "application/octet-stream")
		return nil
	})
	if err != nil {
		vc.Logger.Errorf("unable to get the theme; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get the file"); err != nil {
			vc.Logger.Errorf("unable to get the theme with ID %s; err=%s", themeID, err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the theme with ID %s; responseCode=%d, responseBody=%s", themeID, resp.StatusCode(), string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the theme")
	}
	return resp.Body, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *ThemeClient) GetFile(ctx context.Context, themeID string, path string) ([]byte, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	fmt.Println("Tenant:", vc.Tenant)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.httpClient)

	resp, err := client.GetTemplate0WithResponse(ctx, themeID, path, openapi.DefaultRequestEditors(ctx, vc.Token)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the themes; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get the file"); err != nil {
			vc.Logger.Errorf("unable to get the theme with ID %s and path %s; err=%s", themeID, path, err.Error())
			return nil, "", err
		}

		vc.Logger.Errorf("unable to get the theme with ID %s and path %s; responseCode=%d, responseBody=%s", themeID, path, resp.StatusCode(), string(resp.Body))
		return nil, "", fmt.Errorf("unable to get the file")
	}

	return resp.Body, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *ThemeClient) UpdateFile(ctx context.Context, themeID string, path string, data []byte) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.httpClient)

	buffer, err := httpx.MultipartBuffer(ctx, map[string][]byte{
		"file": data,
	}, nil)
	if err != nil {
		vc.Logger.Errorf("unable to build the buffer; err=%v", err)
		return err
	}

	response, err := client.UpdateThemeTemplateWithBodyWithResponse(ctx, themeID, path, "multipart/form-data", buffer, openapi.DefaultRequestEditors(ctx, vc.Token)...)
	if err != nil {
		vc.Logger.Errorf("unable to update the file; err=%s", err.Error())
		return err
	}

	if response.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to update the file"); err != nil {
			vc.Logger.Errorf("unable to update the theme with ID %s and path %s; err=%s", themeID, path, err.Error())
			return err
		}

		vc.Logger.Errorf("unable to update the theme with ID %s and path %s; responseCode=%d, responseBody=%s", themeID, path, response.StatusCode(), string(response.Body))
		return fmt.Errorf("unable to update the file")
	}

	return nil
}

func (c *ThemeClient) UpdateTheme(ctx context.Context, themeID string, data []byte, metadata map[string]interface{}) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.httpClient)

	fields := map[string]string{}
	if len(metadata) > 0 {
		if configBytes, err := json.Marshal(metadata); err == nil {
			fields["configuration"] = string(configBytes)
		}
	}

	buffer, err := httpx.MultipartBuffer(ctx, map[string][]byte{
		"files": data,
	}, fields)
	if err != nil {
		vc.Logger.Errorf("unable to build the buffer; err=%v", err)
		return err
	}

	response, err := client.UpdateThemeTemplatesWithBodyWithResponse(ctx, themeID, "multipart/form-data", buffer, openapi.DefaultRequestEditors(ctx, vc.Token)...)
	if err != nil {
		vc.Logger.Errorf("unable to update the theme; err=%s", err.Error())
		return err
	}

	if response.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, response.HTTPResponse, "unable to update the theme"); err != nil {
			vc.Logger.Errorf("unable to update the theme with ID %s; err=%s", themeID, err.Error())
			return err
		}

		vc.Logger.Errorf("unable to update the theme with ID %s; responseCode=%d, responseBody=%s", themeID, response.StatusCode(), string(response.Body))
		return fmt.Errorf("unable to update the theme")
	}

	return nil
}
