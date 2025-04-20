package auth

import (
	"context"
	"fmt"
	"net/url"

	"github.com/google/uuid"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	"github.com/ibm-verify/verify-sdk-go/x/randx"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type DeviceAuthTokenCallback func() (*oauth2.Token, error)

// Client represents the
type Client struct {
	// Tenant is the IBM Verify hostname that is used to identify the tenant.
	// The default format is abc.verify.ibm.com. However, custom domains may also
	// be used if configured for the tenant.
	Tenant string

	// ClientAuth represents the client authentication method used.
	ClientAuth ClientAuth

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string

	// Scopes represents optional requestable permissions.
	Scopes []string
}

func (c *Client) TokenWithAPIClient(ctx context.Context, parameters url.Values) (*TokenResponse, error) {
	params, err := c.ClientAuth.GetParameters()
	if err != nil {
		return nil, err
	}

	clientID := params.Get("client_id")
	params.Del("client_id")
	clientSecret := params.Get("client_secret")
	params.Del("client_secret")

	for k := range parameters {
		params.Add(k, parameters.Get(k))
	}

	oauthConfig := &clientcredentials.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		TokenURL:       fmt.Sprintf("https://%s/oauth2/token", c.Tenant),
		AuthStyle:      oauth2.AuthStyleInParams,
		EndpointParams: params,
		Scopes:         c.Scopes,
	}

	t, err := oauthConfig.Token(ctx)
	if err != nil {
		return nil, err
	}

	return NewTokenResponseWithOAuth2Token(t), nil
}

func (c *Client) AuthorizeWithBrowserFlow(ctx context.Context, parameters url.Values) (*AuthorizeResponse, error) {
	params, err := c.ClientAuth.GetParameters()
	if err != nil {
		return nil, err
	}

	var opts []oauth2.AuthCodeOption
	for k := range parameters {
		opts = append(opts, oauth2.SetAuthURLParam(k, parameters.Get(k)))
	}

	verifier := oauth2.GenerateVerifier()
	opts = append(opts, oauth2.S256ChallengeOption(verifier))

	oauthConfig := &oauth2.Config{
		ClientID: params.Get("client_id"),
		Endpoint: oauth2.Endpoint{
			AuthURL: fmt.Sprintf("https://%s/oauth2/authorize", c.Tenant),
		},
		RedirectURL: c.RedirectURL,
		Scopes:      c.Scopes,
	}

	state, err := randx.GenerateRandomString(24, randx.AlphaLower)
	if err != nil {
		// this should never happen, but if it does, this falls back to a UUID.
		state = uuid.NewString()
	}

	return &AuthorizeResponse{
		State:            state,
		AuthCodeURL:      oauthConfig.AuthCodeURL(state, opts...),
		PKCECodeVerifier: verifier,
	}, nil
}

func (c *Client) TokenWithAuthCode(ctx context.Context, authResponse *AuthorizeResponse, callbackParams url.Values) (*TokenResponse, error) {
	// verify if the flow has failed
	if callbackParams.Get("error") != "" {
		return nil, errorsx.G11NError("error: %s, description: %s", callbackParams.Get("error"), callbackParams.Get("error_description"))
	}

	// check if the state matches
	if callbackParams.Get("state") != authResponse.State {
		return nil, errorsx.G11NError("'state' does not match.")
	}

	// do the biz
	params, err := c.ClientAuth.GetParameters()
	if err != nil {
		return nil, err
	}

	clientID := params.Get("client_id")
	params.Del("client_id")
	clientSecret := params.Get("client_secret")
	params.Del("client_secret")

	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://%s/oauth2/authorize", c.Tenant),
			TokenURL: fmt.Sprintf("https://%s/oauth2/token", c.Tenant),
		},
		Scopes:      c.Scopes,
		RedirectURL: c.RedirectURL,
	}

	var opts []oauth2.AuthCodeOption
	if len(params) > 0 {
		for k := range params {
			opts = append(opts, oauth2.SetAuthURLParam(k, params.Get(k)))
		}
	}

	opts = append(opts, oauth2.VerifierOption(authResponse.PKCECodeVerifier))
	t, err := oauthConfig.Exchange(ctx, callbackParams.Get("code"), opts...)
	if err != nil {
		return nil, err
	}

	return NewTokenResponseWithOAuth2Token(t), nil
}

func (c *Client) AuthorizeWithDeviceFlow(ctx context.Context, parameters url.Values) (*DeviceAuthResponse, error) {
	params, err := c.ClientAuth.GetParameters()
	if err != nil {
		return nil, err
	}

	var opts []oauth2.AuthCodeOption
	for k := range parameters {
		opts = append(opts, oauth2.SetAuthURLParam(k, parameters.Get(k)))
	}

	oauthConfig := &oauth2.Config{
		ClientID: params.Get("client_id"),
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: fmt.Sprintf("https://%s/oauth2/device_authorization", c.Tenant),
		},
		Scopes: c.Scopes,
	}

	return oauthConfig.DeviceAuth(ctx, opts...)
}

// TokenWithDeviceFlow polls for the token as part of the device authorization grant flow.
// In the event of a failure, it will return an error.
func (c *Client) TokenWithDeviceFlow(ctx context.Context, deviceAuthResponse *oauth2.DeviceAuthResponse) (*TokenResponse, error) {
	params, err := c.ClientAuth.GetParameters()
	if err != nil {
		return nil, err
	}

	clientID := params.Get("client_id")
	params.Del("client_id")
	clientSecret := params.Get("client_secret")
	params.Del("client_secret")

	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: fmt.Sprintf("https://%s/oauth2/device_authorization", c.Tenant),
			TokenURL:      fmt.Sprintf("https://%s/oauth2/token", c.Tenant),
		},
		Scopes: c.Scopes,
	}

	var opts []oauth2.AuthCodeOption
	if len(params) > 0 {
		for k := range params {
			opts = append(opts, oauth2.SetAuthURLParam(k, params.Get(k)))
		}
	}

	t, err := oauthConfig.DeviceAccessToken(ctx, deviceAuthResponse, opts...)
	if err != nil {
		return nil, err
	}

	return NewTokenResponseWithOAuth2Token(t), nil
}
