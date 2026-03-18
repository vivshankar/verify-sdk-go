package authentication

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/pkg/core/models"
)

const (
	sampleOIDCIdentitySource = `
{
    "attributeMappings": [
        {
            "attrId": "aa41ddbe-586a-4b21-bed8-a95466c2f621",
            "jitpOption": "ALWAYS",
            "idsAttrName": "groupIds"
        },
        {
            "attrId": "idpsurname",
            "jitpOption": "DISABLED",
            "idsAttrName": "surname"
        },
        {
            "attrId": "idpdomain",
            "jitpOption": "DISABLED",
            "idsAttrName": "domain"
        },
        {
            "attrId": "idpusername",
            "jitpOption": "ALWAYS",
            "idsAttrName": "email"
        },
        {
            "attrId": "email",
            "jitpOption": "ALWAYS",
            "idsAttrName": "email"
        }
    ],
    "instanceName": "Test OIDC IdP",
    "enabled": true,
    "predefined": false,
    "properties": [
        {
            "sensitive": false,
            "value": "a-client-id",
            "key": "client_id"
        },
        {
            "sensitive": false,
            "value": "a-client-secret",
            "key": "client_secret"
        },
        {
            "sensitive": false,
            "value": "true",
            "key": "forward_login_hint"
        },
        {
            "sensitive": false,
            "value": "true",
            "key": "forward_max_age"
        },
        {
            "sensitive": false,
            "value": "true",
            "key": "forward_prompt"
        },
        {
            "sensitive": false,
            "value": "BigBlue OIDC IdP",
            "key": "friendly_name"
        },
        {
            "sensitive": false,
            "value": "false",
            "key": "identityLinkingEnabled"
        },
        {
            "sensitive": false,
            "value": "",
            "key": "identityLinkingExternalId"
        },
        {
            "sensitive": false,
            "value": "",
            "key": "identityLinkingExternalIdTransform"
        },
        {
            "sensitive": false,
            "value": "true",
            "key": "jitEnabled"
        },
        {
            "sensitive": false,
            "value": "https://oidc.BigBlue.com/oauth/jwks",
            "key": "jwks_uri"
        },
        {
            "sensitive": false,
            "value": "false",
            "key": "pkce_support"
        },
        {
            "sensitive": false,
            "value": "preferred_username",
            "key": "principalAttribute"
        },
        {
            "sensitive": false,
            "value": "",
            "key": "principalAttributeTransform"
        },
        {
            "sensitive": false,
            "value": "https://oidc.BigBlue.com/oauth",
            "key": "realm"
        },
        {
            "sensitive": false,
            "value": "openid email",
            "key": "scopes"
        },
        {
            "sensitive": false,
            "value": "false",
            "key": "show_admin_user"
        },
		{
			"key":       "show_admin_user_qr",
			"value":     "false",
			"sensitive": false,
		},
		{
			"key":       "show_admin_user_fido",
			"value":     "false",
			"sensitive": false,
		},
        {
            "sensitive": false,
            "value": "true",
            "key": "show_end_user"
        },
		{
			"key":       "show_end_user_qr",
			"value":     "false",
			"sensitive": false,
		},
		{
			"key":       "show_end_user_fido",
			"value":     "false",
			"sensitive": false,
		}
        {
            "sensitive": false,
            "value": "authorization_code",
            "key": "supported_grant_types"
        },
        {
            "sensitive": false,
            "value": "",
            "key": "userInvitationProfile"
        },
        {
            "sensitive": false,
            "value": "false",
            "key": "userInvitationsEnabled"
        },
        {
            "sensitive": false,
            "value": "https://oidc.BigBlue.com/.well-known/openid-configuration",
            "key": "wellknown_endpoint"
        }
    ],
    "sourceTypeId": 19,
    "status": "configured"
}
`
)

type IdentitySourceClient struct {
	Client *http.Client
}

func NewIdentitySourceClient() *IdentitySourceClient {
	return &IdentitySourceClient{}
}

func (c *IdentitySourceClient) CreateIdentitySource(ctx context.Context, identitySource *models.IdentitySource) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	defaultErr := errorsx.G11NError("unable to create identitySource")

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.CreateIdentitySourceV2WithResponse(ctx, *identitySource, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("Unable to create identitySource; err=%v", err)
		return "", defaultErr
	}

	if resp.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, resp.Body, "unable to create identitySource"); err != nil {
			vc.Logger.Errorf("unable to create the identitySource; err=%s", err.Error())
			return "", errorsx.G11NError("unable to create the identitySource; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to create the identitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", errorsx.G11NError("unable to create the identitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	uri, _ := resp.HTTPResponse.Location()
	return uri.String(), nil
}

func (c *IdentitySourceClient) GetIdentitySource(ctx context.Context, id string) (*models.IdentitySource, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.GetInstanceV2WithResponse(ctx, id, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the IdentitySource; err=%s", err.Error())
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, resp.Body, "unable to get IdentitySource"); err != nil {
			vc.Logger.Errorf("unable to get the IdentitySource; err=%s", err.Error())
			return nil, err
		}

		vc.Logger.Errorf("unable to get the IdentitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, errorsx.G11NError("unable to get the IdentitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	IdentitySource := &models.IdentitySource{}
	if err = json.Unmarshal(resp.Body, IdentitySource); err != nil {
		return nil, err
	}

	return IdentitySource, nil
}

func (c *IdentitySourceClient) GetIdentitySources(ctx context.Context, criteria *models.GetInstancesV2Params) (*models.IdentitySourceList, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.GetInstancesV2WithResponse(ctx, criteria, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the IdentitySources; err=%s", err.Error())
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, resp.Body, "unable to get IdentitySources"); err != nil {
			vc.Logger.Errorf("unable to get the IdentitySources; err=%s", err.Error())
			return nil, err
		}

		vc.Logger.Errorf("unable to get the IdentitySources; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, errorsx.G11NError("unable to get the IdentitySources; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	list := &models.IdentitySourceList{}
	if err = json.Unmarshal(resp.Body, &list); err != nil {
		vc.Logger.Errorf("unable to get the IdentitySources; err=%s, body=%s", err, string(resp.Body))
		return nil, err
	}

	return list, nil
}

func (c *IdentitySourceClient) DeleteIdentitySource(ctx context.Context, id string) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.DeleteIdentitySourceV2WithResponse(ctx, id, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete the IdentitySource; err=%s", err.Error())
		return errorsx.G11NError("unable to delete the IdentitySource; err=%s", err.Error())
	}

	if resp.StatusCode() != http.StatusNoContent {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, resp.Body, "unable to delete IdentitySource"); err != nil {
			vc.Logger.Errorf("unable to delete the IdentitySource; err=%s", err.Error())
			return errorsx.G11NError("unable to delete the IdentitySource; err=%s", err.Error())
		}

		vc.Logger.Errorf("unable to delete the IdentitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("unable to delete the IdentitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *IdentitySourceClient) UpdateIdentitySource(ctx context.Context, id string, identitySource *models.IdentitySource) error {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)

	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.UpdateIdentitySourceV2WithResponse(ctx, id, *identitySource, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, resp.Body, "unable to update Identity provider"); err != nil {
			vc.Logger.Errorf("unable to update the Identity provider; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("unable to update identitySource; err=%v", err)
		return errorsx.G11NError("unable to update identitySource; err=%v", err)
	}

	if resp.StatusCode() != http.StatusNoContent {
		vc.Logger.Errorf("failed to update identitySource; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("failed to update identitySource ; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func IdentitySourceExample() *models.IdentitySource {
	identitySource := &models.IdentitySource{}

	_ = json.Unmarshal([]byte(sampleOIDCIdentitySource), identitySource)
	return identitySource
}
