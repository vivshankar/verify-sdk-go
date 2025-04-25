package applications

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
)

const (
	apiApplications = "v1.0/applications"
)

type ApplicationListResponse struct {
	Embedded   Embedded `json:"_embedded" yaml:"_embedded"`
	TotalCount int      `json:"totalCount" yaml:"totalCount"`
}

type Embedded struct {
	Applications []Application `json:"applications" yaml:"applications"`
}

type Application struct {
	Name                   string                 `json:"name" yaml:"name"`
	TemplateID             string                 `json:"templateId" yaml:"templateId"`
	Links                  Links                  `json:"_links" yaml:"_links"`
	Providers              Providers              `json:"providers" yaml:"providers"`
	Provisioning           Provisioning           `json:"provisioning" yaml:"provisioning"`
	AttributeMappings      []AttributeMapping     `json:"attributeMappings" yaml:"attributeMappings,omitempty"`
	ApplicationState       bool                   `json:"applicationState" yaml:"applicationState,omitempty"`
	ApprovalRequired       bool                   `json:"approvalRequired" yaml:"approvalRequired,omitempty"`
	SignonState            bool                   `json:"signonState" yaml:"signonState,omitempty"`
	Description            string                 `json:"description" yaml:"description,omitempty"`
	ProvisioningMode       string                 `json:"provisioningMode" yaml:"provisioningMode,omitempty"`
	IdentitySources        []string               `json:"identitySources" yaml:"identitySources,omitempty"`
	VisibleOnLaunchpad     bool                   `json:"visibleOnLaunchpad" yaml:"visibleOnLaunchpad,omitempty"`
	Customization          Customization          `json:"customization" yaml:"customization,omitempty"`
	DevportalSettings      DevportalSettings      `json:"devportalSettings" yaml:"devportalSettings,omitempty"`
	APIAccessClients       []APIAccessClients     `json:"apiAccessClients" yaml:"apiAccessClients,omitempty"`
	CustomIcon             string                 `json:"customIcon" yaml:"customIcon,omitempty"`
	DefaultIcon            string                 `json:"defaultIcon" yaml:"defaultIcon,omitempty"`
	AdaptiveAuthentication AdaptiveAuthentication `json:"adaptiveAuthentication" yaml:"adaptiveAuthentication,omitempty"`
	Target                 map[string]bool        `json:"target" yaml:"target,omitempty"`
}
type Customization struct {
	ThemeID string `json:"themeId" yaml:"themeId,omitempty"`
}
type AdaptiveAuthentication struct {
	Platform    string `json:"platform" yaml:"platform,omitempty"`
	LicenseData string `json:"licenseData" yaml:"licenseData,omitempty"`
	StorageLink string `json:"storageLink" yaml:"storageLink,omitempty"`
}
type DevportalSettings struct {
	GrantTypes                   GrantTypes         `json:"grantTypes" yaml:"grantTypes,omitempty"`
	AuthPolicy                   AuthPolicy         `json:"authPolicy" yaml:"authPolicy,omitempty"`
	ExtendedProperties           map[string]string  `json:"extendedProperties" yaml:"extendedProperties,omitempty"`
	IdentitySources              []string           `json:"identitySources" yaml:"identitySources,omitempty"`
	SendAllKnownUserapplications string             `json:"sendAllKnownUserapplications" yaml:"sendAllKnownUserapplications,omitempty"`
	AttributeMappings            []AttributeMapping `json:"attributeMappings" yaml:"attributeMappings,omitempty"`
}
type AuthPolicy struct {
	ID               string           `json:"id" yaml:"id,omitempty"`
	Name             string           `json:"name" yaml:"name,omitempty"`
	GrantTypes       []GrantTypeEntry `json:"grantTypes" yaml:"grantTypes,omitempty"`
	ErrorCode        string           `json:"errorCode" yaml:"errorCode,omitempty"`
	ErrorDescription string           `json:"errorDescription" yaml:"errorDescription,omitempty"`
}
type GrantTypeEntry struct {
	Name  string `json:"name" yaml:"name",omitempty`
	Value bool   `json:"value" yaml:"value,omitempty"`
}

type Links struct {
	Self Self `json:"self" yaml:"self,omitempty"`
}

type Self struct {
	Href string `json:"href" yaml:"href,omitempty"`
}

type Providers struct {
	SSO      SSO      `json:"sso" yaml:"sso"`
	SAML     SAML     `json:"saml" yaml:"saml"`
	Bookmark Bookmark `json:"bookmark" yaml:"bookmark"`
	OIDC     OIDC     `json:"oidc" yaml:"oidc,omitempty"`
	WSFed    WSFed    `json:"wsfed" yaml:"wsfed,omitempty"`
}

type SSO struct {
	DomainName             string `json:"domainName" yaml:"domainName"`
	UserOptions            string `json:"userOptions" yaml:"userOptions,omitempty"`
	SPSSOURL               string `json:"spssoUrl" yaml:"spssoUrl,omitempty"`
	TargetURL              string `json:"targetUrl" yaml:"targetUrl,omitempty"`
	IDPInitiatedSSOSupport string `json:"idpInitiatedSSOSupport" yaml:"idpInitiatedSSOSupport,omitempty"`
}

type SAML struct {
	JustInTimeProvisioning   string              `json:"justInTimeProvisioning" yaml:"justInTimeProvisioning,omitempty"`
	Properties               SAMLProperties      `json:"properties" yaml:"properties"`
	AssertionConsumerService []interface{}       `json:"assertionConsumerService" yaml:"assertionConsumerService"`
	SingleLogoutService      []interface{}       `json:"singleLogoutService" yaml:"singleLogoutService"`
	AdditionalProperties     []interface{}       `json:"additionalProperties" yaml:"additionalProperties"`
	ManageNameIDService      ManageNameIDService `json:"manageNameIDService" yaml:"manageNameIDService"`
}

type SAMLProperties struct {
	CompanyName                      string `json:"companyName" yaml:"companyName,omitempty"`
	GenerateUniqueID                 string `json:"generateUniqueID" yaml:"generateUniqueID,omitempty"`
	SignAuthnResponse                string `json:"signAuthnResponse" yaml:"signAuthnResponse,omitempty"`
	SignatureAlgorithm               string `json:"signatureAlgorithm" yaml:"signatureAlgorithm,omitempty"`
	ValidateAuthnRequest             string `json:"validateAuthnRequest" yaml:"validateAuthnRequest,omitempty"`
	EncryptAssertion                 string `json:"encryptAssertion" yaml:"encryptAssertion,omitempty"`
	ICIReservedSubjectNameID         string `json:"ici_reserved_subjectNameID" yaml:"ici_reserved_subjectNameID,omitempty"`
	IncludeAllapplications           string `json:"includeAllapplications" yaml:"includeAllapplications,omitempty"`
	DefaultNameIdFormat              string `json:"defaultNameIdFormat" yaml:"defaultNameIdFormat,omitempty"`
	ProviderID                       string `json:"providerId" yaml:"providerId"`
	AssertionConsumerServiceURL      string `json:"assertionConsumerServiceUrl" yaml:"assertionConsumerServiceUrl"`
	SignatureValidationKeyIdentifier string `json:"signatureValidationKeyIdentifier" yaml:"signatureValidationKeyIdentifier,omitempty"`
	BlockEncryptionAlgorithm         string `json:"blockEncryptionAlgorithm" yaml:"blockEncryptionAlgorithm,omitempty"`
	EncryptionKeyIdentifier          string `json:"encryptionKeyIdentifier" yaml:"encryptionKeyIdentifier,omitempty"`
	UniqueID                         string `json:"uniqueID" yaml:"uniqueID,omitempty"`
	SessionNotOnOrAfter              string `json:"sessionNotOnOrAfter" yaml:"sessionNotOnOrAfter,omitempty"`
	SigningKeyIdentifier             string `json:"signingKeyIdentifier" yaml:"signingKeyIdentifier,omitempty"`
}

type ManageNameIDService struct {
	URL string `json:"url" yaml:"url"`
}

type Bookmark struct {
	BookmarkURL string `json:"bookmarkUrl" yaml:"bookmarkUrl"`
}

type OIDC struct {
	Properties              OIDCProperties      `json:"properties" yaml:"properties,omitempty"`
	GrantProperties         GrantProperties     `json:"grantProperties" yaml:"grantProperties"`
	Token                   Token               `json:"token" yaml:"token,omitempty"`
	JWTBearerProperties     JWTBearerProperties `json:"jwtBearerProperties" yaml:"jwtBearerProperties,omitempty"`
	ApplicationURL          string              `json:"applicationUrl" yaml:"applicationUrl,omitempty"`
	RestrictScopes          string              `json:"restrictScopes" yaml:"restrictScopes,omitempty"`
	Scopes                  []interface{}       `json:"scopes" yaml:"scopes,omitempty"`
	Entitlements            []interface{}       `json:"entitlements" yaml:"entitlements,omitempty"`
	RestrictEntitlements    bool                `json:"restrictEntitlements" yaml:"restrictEntitlements,omitempty"`
	ConsentAction           string              `json:"consentAction" yaml:"consentAction,omitempty"`
	RequirePKCEVerification string              `json:"requirePkceVerification" yaml:"requirePkceVerification,omitempty"`
}

type OIDCProperties struct {
	GrantTypes                   GrantTypes    `json:"grantTypes" yaml:"grantTypes,omitempty"`
	RedirectURIs                 []interface{} `json:"redirectUris" yaml:"redirectUris,omitempty"`
	IDTokenSigningAlg            string        `json:"idTokenSigningAlg" yaml:"idTokenSigningAlg,omitempty"`
	AccessTokenExpiry            int           `json:"accessTokenExpiry" yaml:"accessTokenExpiry,omitempty"`
	RefreshTokenExpiry           int           `json:"refreshTokenExpiry" yaml:"refreshTokenExpiry,omitempty"`
	DoNotGenerateClientSecret    string        `json:"doNotGenerateClientSecret" yaml:"doNotGenerateClientSecret,omitempty"`
	GenerateRefreshToken         string        `json:"generateRefreshToken" yaml:"generateRefreshToken,omitempty"`
	RenewRefreshTokenExpiry      int           `json:"renewRefreshTokenExpiry" yaml:"renewRefreshTokenExpiry,omitempty"`
	SignIDToken                  string        `json:"signIdToken" yaml:"signIdToken,omitempty"`
	SigningCertificate           string        `json:"signingCertificate" yaml:"signingCertificate,omitempty"`
	ClientID                     string        `json:"clientId" yaml:"clientId,omitempty"`
	ClientSecret                 string        `json:"clientSecret" yaml:"clientSecret,omitempty"`
	SendAllKnownUserapplications string        `json:"sendAllKnownUserapplications" yaml:"sendAllKnownUserapplications,omitempty"`
	JWKSURI                      string        `json:"jwksUri" yaml:"jwksUri,omitempty"`
	ConsentType                  string        `json:"consentType" yaml:"consentType,omitempty"`
	RenewRefreshToken            string        `json:"renewRefreshToken" yaml:"renewRefreshToken,omitempty"`
	IDTokenEncryptAlg            string        `json:"idTokenEncryptAlg" yaml:"idTokenEncryptAlg,omitempty"`
	IDTokenEncryptEnc            string        `json:"idTokenEncryptEnc" yaml:"idTokenEncryptEnc,omitempty"`
	IDTokenEncryptKey            string        `json:"idTokenEncryptKey" yaml:"idTokenEncryptKey,omitempty"`
}

type GrantTypes struct {
	AuthorizationCode bool `json:"authorizationCode" yaml:"authorizationCode,omitempty"`
	Implicit          bool `json:"implicit" yaml:"implicit,omitempty"`
	DeviceFlow        bool `json:"deviceFlow" yaml:"deviceFlow,omitempty"`
	ROPC              bool `json:"ropc" yaml:"ropc,omitempty"`
	JWTBearer         bool `json:"jwtBearer" yaml:"jwtBearer,omitempty"`
	PolicyAuth        bool `json:"policyAuth" yaml:"policyAuth,omitempty"`
	ClientCredentials bool `json:"clientCredentials" yaml:"clientCredentials,omitempty"`
	TokenExchange     bool `json:"tokenExchange" yaml:"tokenExchange,omitempty"`
}

type GrantProperties struct {
	GenerateDeviceFlowQRCode string `json:"generateDeviceFlowQRCode" yaml:"generateDeviceFlowQRCode,omitempty"`
}

type Token struct {
	AccessTokenType   string        `json:"accessTokenType" yaml:"accessTokenType"`
	Audiences         []interface{} `json:"audiences" yaml:"audiences,omitempty"`
	AttributeMappings []interface{} `json:"attributeMappings" yaml:"attributeMappings,omitempty"`
}

type JWTBearerProperties struct {
	UserIdentifier string `json:"userIdentifier" yaml:"userIdentifier,omitempty"`
	IdentitySource string `json:"identitySource" yaml:"identitySource,omitempty"`
}
type Scopes struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description,omitempty"`
}
type WSFed struct {
	Properties WSFedProperties `json:"properties" yaml:"properties,omitempty"`
}

type WSFedProperties struct {
	ActiveProfile            ActiveProfile   `json:"activeProfile" yaml:"activeProfile,omitempty"`
	SigningSettings          SigningSettings `json:"signingSettings" yaml:"signingSettings,omitempty"`
	CallbackURL              string          `json:"callbackURL" yaml:"callbackURL,omitempty"`
	ProviderID               string          `json:"providerId" yaml:"providerId,omitempty"`
	MultipleDomainsEnabled   string          `json:"multipleDomainsEnabled" yaml:"multipleDomainsEnabled,omitempty"`
	ICIReservedSubjectNameID string          `json:"ici_reserved_subjectNameID" yaml:"ici_reserved_subjectNameID,omitempty"`
	AdditionalProperties     []interface{}   `json:"additionalProperties" yaml:"additionalProperties"`
}

type ActiveProfile struct {
	DefaultRealm string `json:"defaultRealm" yaml:"defaultRealm,omitempty"`
}

type SigningSettings struct {
	SignSAMLAssertion  string      `json:"signSamlAssertion" yaml:"signSamlAssertion,omitempty"`
	KeyLabel           interface{} `json:"keyLabel" yaml:"keyLabel,omitempty"`
	SignatureAlgorithm string      `json:"signatureAlgorithm" yaml:"signatureAlgorithm,omitempty"`
}

type Provisioning struct {
	Extension                Extension            `json:"extension" yaml:"extension,omitempty"`
	AttributeMappings        []AttributeMapping   `json:"attributeMappings" yaml:"attributeMappings,omitempty"`
	Policies                 ProvisioningPolicies `json:"policies" yaml:"policies,omitempty"`
	SendNotifications        bool                 `json:"sendNotifications" yaml:"sendNotifications"`
	ReverseAttributeMappings []AttributeMapping   `json:"reverseAttributeMappings" yaml:"reverseAttributeMappings,omitempty"`
	Authentication           Authentication       `json:"authentication" yaml:"authentication,omitempty"`
	ProvisioningState        string               `json:"provisioningState" yaml:"provisioningState,omitempty"`
}

type Extension struct {
	Properties map[string]string `json:"properties" yaml:"properties,omitempty"`
}

type AttributeMapping struct {
	TargetName       string `json:"targetName" yaml:"targetName,omitempty"`
	SourceID         string `json:"sourceId" yaml:"sourceId,omitempty"`
	OutboundTracking bool   `json:"outboundTracking" yaml:"outboundTracking,omitempty"`
}

type ProvisioningPolicies struct {
	AdoptionPolicy AdoptionPolicy `json:"adoptionPolicy" yaml:"adoptionPolicy,omitempty"`
	ProvPolicy     string         `json:"provPolicy" yaml:"provPolicy,omitempty"`
	DeProvPolicy   string         `json:"deProvPolicy" yaml:"deProvPolicy,omitempty"`
	DeProvAction   string         `json:"deProvAction" yaml:"deProvAction,omitempty"`
	GracePeriod    int64          `json:"gracePeriod" yaml:"gracePeriod,omitempty"`
}

type AdoptionPolicy struct {
	Matchingapplications []AttributeMapping `json:"matchingapplications" yaml:"matchingapplications,omitempty"`
}

type Authentication struct {
	Properties map[string]string `json:"properties" yaml:"properties,omitempty"`
}

type APIAccessClients struct {
	AccessTokenLifetime int32    `json:"accessTokenLifetime" yaml:"accessTokenLifetime"`
	AccessTokenType     string   `json:"accessTokenType" yaml:"accessTokenType"`
	ClientName          string   `json:"clientName" yaml:"clientName"`
	ClientID            string   `json:"clientId" yaml:"clientId,omitempty"`
	Enabled             bool     `json:"enabled" yaml:"enabled"`
	JWTSigningAlg       string   `json:"jwtSigningAlg" yaml:"jwtSigningAlg,omitempty"`
	SignKeyLabel        string   `json:"signKeyLabel" yaml:"signKeyLabel,omitempty"`
	RestrictScopes      bool     `json:"restrictScopes" yaml:"restrictScopes,omitempty"`
	IPFilterOp          string   `json:"ipFilterOp" yaml:"ipFilterOp,omitempty"`
	IPFilters           []string `json:"ipFilters" yaml:"ipFilters,omitempty"`
	JWKURI              string   `json:"jwkUri" yaml:"jwkUri,omitempty"`
	Scopes              []string `json:"scopes" yaml:"scopes,omitempty"`
	DefaultEntitlements []string `json:"defaultEntitlements" yaml:"defaultEntitlements,omitempty"`
}

type ApplicationClient struct {
	Client *http.Client
}

func NewApplicationClient() *ApplicationClient {
	return &ApplicationClient{
		Client: &http.Client{},
	}
}

func (c *ApplicationClient) GetApplication(ctx context.Context, name string) (*Application, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	if vc == nil {
		return nil, "", errorsx.G11NError("VerifyContext is nil")
	}

	templateId, err := c.GetApplicationId(ctx, name)
	if err != nil {
		vc.Logger.Errorf("unable to get the group ID; err=%s", err.Error())
		return nil, "", err
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s/%s", vc.Tenant, apiApplications, templateId))

	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + vc.Token},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		vc.Logger.Errorf("unable to get an Application; err=%s", err.Error())
		return nil, "", err
	}
	req.Header = headers

	response, err := c.Client.Do(req)
	if err != nil {
		vc.Logger.Errorf("unable to get an Application; err=%s", err.Error())
		return nil, "", err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		vc.Logger.Errorf("unable to read response body; err=%s", err.Error())
		return nil, "", err
	}

	if response.StatusCode != http.StatusOK {
		vc.Logger.Errorf("unable to get Application; code=%d, body=%s", response.StatusCode, string(body))
		return nil, "", errorsx.G11NError("unable to get Application")
	}

	app := &Application{}
	if err = json.Unmarshal(body, app); err != nil {
		vc.Logger.Errorf("unable to unmarshal response; err=%s", err.Error())
		return nil, "", errorsx.G11NError("unable to get Application")
	}

	return app, u.String(), nil
}

func (c *ApplicationClient) GetApplicationId(ctx context.Context, name string) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	if vc == nil {
		return "", errorsx.G11NError("VerifyContext is nil")
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", vc.Tenant, apiApplications))
	q := u.Query()
	q.Set("search", fmt.Sprintf(`"q=%s"`, name))
	u.RawQuery = q.Encode()

	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + vc.Token},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		vc.Logger.Errorf("unable to create request; err=%s", err.Error())
		return "", err
	}
	req.Header = headers

	respo, err := c.Client.Do(req)
	if err != nil {
		vc.Logger.Errorf("unable to query applications; err=%s", err.Error())
		return "", err
	}
	defer respo.Body.Close()

	body, err := io.ReadAll(respo.Body)
	if err != nil {
		vc.Logger.Errorf("unable to read response body; err=%s", err.Error())
		return "", err
	}

	if respo.StatusCode != http.StatusOK {
		vc.Logger.Errorf("unable to query applications; code=%d, body=%s", respo.StatusCode, string(body))
		return "", errorsx.G11NError("unable to query applications: status=%d, body=%s", respo.StatusCode, string(body))
	}

	var resp ApplicationListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", errorsx.G11NError("failed to parse API response: %w", err)
	}

	if len(resp.Embedded.Applications) == 0 {
		return "", errorsx.G11NError("no application found with name %s", name)
	}

	for _, app := range resp.Embedded.Applications {
		if app.Name == name {
			if app.Links.Self.Href == "" {
				return "", errorsx.G11NError("no self link found for application %s", name)
			}
			id := app.Links.Self.Href
			if idx := strings.LastIndex(id, "/"); idx != -1 {
				id = id[idx+1:]
			}
			return id, nil
		}
	}

	return "", errorsx.G11NError("no application found with exact name %s", name)
}

func (c *ApplicationClient) GetApplications(ctx context.Context, search string, sort string, page int, limit int) (*ApplicationListResponse, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	if vc == nil {
		return nil, "", errorsx.G11NError("VerifyContext is nil")
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s/%s", vc.Tenant, apiApplications))
	q := u.Query()
	if len(search) > 0 {
		q.Set("search", fmt.Sprintf(`"q=%s"`, search))
	}
	if len(sort) > 0 {
		q.Set("sort", sort)
	}
	if page > 0 {
		q.Set("page", fmt.Sprintf("%d", page))
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	u.RawQuery = q.Encode()

	headers := http.Header{
		"Accept":        []string{"application/json"},
		"Authorization": []string{"Bearer " + vc.Token},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		vc.Logger.Errorf("unable to create request; err=%s", err.Error())
		return nil, "", err
	}
	req.Header = headers

	respo, err := c.Client.Do(req)
	if err != nil {
		vc.Logger.Errorf("unable to get Applications; err=%s", err.Error())
		return nil, "", err
	}
	defer respo.Body.Close()

	body, err := io.ReadAll(respo.Body)
	if err != nil {
		vc.Logger.Errorf("unable to read response body; err=%s", err.Error())
		return nil, "", err
	}

	if respo.StatusCode != http.StatusOK {
		vc.Logger.Errorf("unable to get the Applications; code=%d, body=%s", respo.StatusCode, string(body))
		return nil, "", errorsx.G11NError("unable to get the Applications")

	}

	applicationsResponse := &ApplicationListResponse{}
	if err = json.Unmarshal(body, applicationsResponse); err != nil {
		vc.Logger.Errorf("unable to unmarshal response; err=%s", err.Error())
		return nil, "", errorsx.G11NError("unable to get the Applications")
	}

	return applicationsResponse, u.String(), nil
}
