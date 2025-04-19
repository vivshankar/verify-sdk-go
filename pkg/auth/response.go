package auth

import "golang.org/x/oauth2"

type AuthorizeResponse struct {
	State string

	AuthCodeURL string

	PKCECodeVerifier string
}

type DeviceAuthResponse = oauth2.DeviceAuthResponse

// TokenResponse defines model for TokenResponse.
type TokenResponse struct {
	// AccessToken The access token that is issued by the authorization server.
	AccessToken string `json:"access_token"`

	// ExpiresIn The lifetime, in seconds, of the access token.
	ExpiresIn int64 `json:"expires_in"`

	// GrantID The grant identifier of this authorization grant.
	GrantID string `json:"grant_id"`

	// IDToken The ID token that is issued by the authorization server, when the requested scope contains 'openid'.
	IDToken string `json:"id_token,omitempty"`

	// RefreshToken The refresh token that is used to obtain new access tokens. It is only available for authorization_code grant if the refresh_token grant is enabled.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Scope A space-delimited list of scopes that are associated with this access token.
	Scope string `json:"scope,omitempty"`

	// TokenType The type of the access token.
	TokenType string `json:"token_type"`
}

func NewTokenResponseWithOAuth2Token(t *oauth2.Token) *TokenResponse {
	tr := &TokenResponse{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		ExpiresIn:    t.ExpiresIn,
		TokenType:    t.TokenType,
	}

	if grantID, ok := t.Extra("grant_id").(string); ok {
		tr.GrantID = grantID
	}

	if idToken, ok := t.Extra("id_token").(string); ok {
		tr.IDToken = idToken
	}

	if scope, ok := t.Extra("scope").(string); ok {
		tr.Scope = scope
	}

	return tr
}
