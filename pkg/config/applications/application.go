package applications

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	typesx "github.com/ibm-verify/verify-sdk-go/x/types"

	. "github.com/ibm-verify/verify-sdk-go/pkg/core/models"
)

type ApplicationClient struct {
	Client *http.Client
}

func NewApplicationClient() *ApplicationClient {
	return &ApplicationClient{
		Client: &http.Client{},
	}
}

func (c *ApplicationClient) CreateApplication(ctx context.Context, application *ApplicationSettings) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{
		Accept:      "application/json",
		ContentType: "application/json",
		Token:       vc.Token,
	}
	body, err := json.Marshal(application)
	if err != nil {
		vc.Logger.Errorf("Unable to marshal application data; err=%s", err.Error())
		return "", errorsx.G11NError("unable to marshal application data")
	}

	resp, err := client.CreateApplicationWithBodyWithResponse(ctx, "application/json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to create an Application; err=%s", err.Error())
		return "", errorsx.G11NError("unable to create application")
	}

	if resp.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, resp.Body, "unable to create application"); err != nil {
			vc.Logger.Errorf("unable to create the application; err=%s", err.Error())
			return "", err
		}
		vc.Logger.Errorf("Failed to create application; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", errorsx.G11NError("failed to create application; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	m := map[string]any{}
	if err := json.Unmarshal(resp.Body, &m); err != nil {
		vc.Logger.Errorf("Failed to unmarshal application response; err=%s", err.Error())
		return "", errorsx.G11NError("unable to parse response")
	}

	links := typesx.Map(m).SafeMap("_links", nil)
	self := typesx.Map(links).SafeMap("self", nil)
	href := typesx.Map(self).SafeString("href", "")
	if len(href) == 0 {
		vc.Logger.Errorf("Response missing _links.self.href field; body=%s", string(body))
		return "", errorsx.G11NError("missing _links.self.href")
	}

	return href, nil
}

func (c *ApplicationClient) UpdateApplication(ctx context.Context, applicationID string, application *ApplicationSettings) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	if application == nil {
		vc.Logger.Errorf("application object is nil")
		return errorsx.G11NError("application object is nil")
	}

	headers := &openapi.Headers{
		Accept:      "application/json",
		ContentType: "*/*",
		Token:       vc.Token,
	}

	body, err := json.Marshal(application)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the Application; err=%s", err.Error())
		return errorsx.G11NError("unable to marshal the Application data")
	}

	resp, err := client.UpdateApplicationWithBodyWithResponse(ctx, applicationID, "*/*", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to update an Application; err=%s", err.Error())
		return errorsx.G11NError("unable to update application")
	}

	if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, resp.Body, "unable to update application"); err != nil {
			vc.Logger.Errorf("unable to update the application; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("Failed to update application; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("failed to update application; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *ApplicationClient) GetApplication(ctx context.Context, id string) (*ApplicationSettings, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.GetApplication(ctx, id, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the Application; err=%s", err.Error())
		return nil, err
	}

	buf, err := io.ReadAll(resp.Body)
	defer func() { _ = resp.Body.Close() }()
	if err != nil {
		vc.Logger.Errorf("unable to read the attributes body; err=%v", err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp, buf, "unable to get application"); err != nil {
			vc.Logger.Errorf("unable to get the application; err=%s", err.Error())
			return nil, err
		}

		vc.Logger.Errorf("unable to get the application; code=%d, body=%s", resp.StatusCode, string(buf))
		return nil, errorsx.G11NError("unable to get the application")
	}

	app := &ApplicationSettings{}
	if err = json.Unmarshal(buf, app); err != nil {
		vc.Logger.Errorf("unable to unmarshal response; err=%s", err.Error())
		return nil, errorsx.G11NError("unable to get Application")
	}

	return app, nil
}

func (c *ApplicationClient) GetApplications(ctx context.Context, criteria *SearchApplicationsParams) (*ApplicationListResponse, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}

	if len(criteria.Search) > 0 {
		criteria.Search = typesx.AddDoubleQuotesIfNotFound(criteria.Search)
	}

	resp, err := client.SearchApplicationsWithResponse(ctx, criteria, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get Applications; err=%s", err.Error())
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, resp.Body, "unable to get Applications"); err != nil {
			vc.Logger.Errorf("unable to get the Applications; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
			return nil, err
		}

		vc.Logger.Errorf("unable to get the Applications; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, errorsx.G11NError("unable to get the Applications; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	applicationsResponse := &ApplicationListResponse{}
	if err = json.Unmarshal(resp.Body, applicationsResponse); err != nil {
		vc.Logger.Errorf("unable to unmarshal response; err=%s", err.Error())
		return nil, err
	}

	return applicationsResponse, nil
}

func (c *ApplicationClient) DeleteApplication(ctx context.Context, id string) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{
		Token:       vc.Token,
		ContentType: "application/json",
	}

	resp, err := client.DeleteApplicationWithResponse(ctx, id, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete the Application; err=%s", err.Error())
		return errorsx.G11NError("unable to delete the Application; err=%s", err.Error())
	}

	if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, resp.Body, "unable to update application"); err != nil {
			vc.Logger.Errorf("unable to delete the application; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("Failed to delete application; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("failed to delete application; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func populateCommonFields(application *ApplicationSettings) {
	application.VisibleOnLaunchpad = true
	application.ApplicationState = true
	application.TemplateID = "1"
	application.Owners = []ApplicationOwner{
		"user-id-in-tenant",
	}
}

func SAMLApplicationExample() *ApplicationSettings {
	application := &ApplicationSettings{}
	populateCommonFields(application)
	application.Description = "Example SAML app"

	application.Providers = ApplicationSignOnSettings{
		Saml: &ApplicationSAMLSettings{
			JustInTimeProvisioning: "false",
			Properties: SAMLPropertiesBean{
				CompanyName:                 "BigBlue",
				GenerateUniqueID:            false,
				ValidateAuthnRequest:        true,
				EncryptAssertion:            false,
				SubjectNameID:               "1",
				IncludeAllAttributes:        false,
				ProviderID:                  "https://sso.dune.com/saml20sp",
				AssertionConsumerServiceURL: "https://sso.dune.com/saml20sp/assert",
			},
		},
		Sso: SSOBean{
			SpssoURL:               "https://samlapp.dune.com/login",
			IdpInitiatedSSOSupport: false,
			UserOptions:            "saml",
		},
	}

	return application
}

func OIDCApplicationExample() *ApplicationSettings {
	application := &ApplicationSettings{}
	populateCommonFields(application)
	application.TemplateID = "998"
	application.Description = "Example OIDC app"

	application.Providers = ApplicationSignOnSettings{
		Oidc: &ApplicationOIDCSettings{
			ApplicationURL: "https://bbb.dune.com",
			ConsentAction:  ApplicationOIDCSettingsConsentActionAlwaysPrompt,
			Properties: &OIDCPropertiesBean{
				AccessTokenExpiry: 300,
				ClientID:          "a-client-id",
				ClientSecret:      "a-client-secret",
				GrantTypes: &GrantTypesBean{
					AuthorizationCode: true,
				},
				GenerateRefreshToken:    true,
				RefreshTokenExpiry:      86400,
				RenewRefreshTokenExpiry: 86400,
				RenewRefreshToken:       true,
				AdditionalConfig: &AdditionalConfiguration{
					AuthorizeRequestMap: []ClientEnrichmentMap{
						{
							Name:   "scope",
							Custom: `requestContext.scope.filter(x, x == "foo")`,
						},
					},
				},
			},
		},
		Sso: SSOBean{
			IdpInitiatedSSOSupport: false,
			UserOptions:            "oidc",
		},
	}

	return application
}
