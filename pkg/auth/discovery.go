package auth

const (
	DiscoveryEndpoint = "/.well-known/openid-configuration"
)

type OpenIDConfiguration struct {
	// Issuer is the identifier of the OP and is used in the tokens as `iss` claim.
	Issuer string `json:"issuer,omitempty"`

	// AuthorizationEndpoint is the URL of the OAuth 2.0 Authorization Endpoint where all user interactive login start
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`

	// TokenEndpoint is the URL of the OAuth 2.0 Token Endpoint where all tokens are issued, except when using Implicit Flow
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// IntrospectionEndpoint is the URL of the OAuth 2.0 Introspection Endpoint.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// UserinfoEndpoint is the URL where an access_token can be used to retrieve the Userinfo.
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`

	// RevocationEndpoint is the URL of the OAuth 2.0 Revocation Endpoint.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// EndSessionEndpoint is a URL where the RP can perform a redirect to request that the End-User be logged out at the OP.
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`

	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`

	UserAuthorizationEndpoint string `json:"user_authorization_endpoint,omitempty"`

	// JSONWebKeySetURI is the URL of the JSON Web Key Set. This site contains the signing keys that RPs can use to validate the signature.
	// It may also contain the OP's encryption keys that RPs can use to encrypt request to the OP.
	JSONWebKeySetURI string `json:"jwks_uri,omitempty"`

	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`

	MTLSEndpointAliases *MTLSEndpointAliases `json:"mtls_endpoint_aliases,omitempty"`

	// RegistrationEndpoint is the URL for the Dynamic Client Registration.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// ScopesSupported lists an array of supported scopes. This list must not include every supported scope by the OP.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// ResponseTypesSupported contains a list of the OAuth 2.0 response_type values that the OP supports (code, id_token, token id_token, ...).
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`

	// ResponseModesSupported contains a list of the OAuth 2.0 response_mode values that the OP supports. If omitted, the default value is ["query", "fragment"].
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	// GrantTypesSupported contains a list of the OAuth 2.0 grant_type values that the OP supports. If omitted, the default value is ["authorization_code", "implicit"].
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// ACRValuesSupported contains a list of Authentication Context Class References that the OP supports.
	ACRValuesSupported []string `json:"acr_values_supported,omitempty"`

	// SubjectTypesSupported contains a list of Subject Identifier types that the OP supports (pairwise, public).
	SubjectTypesSupported []string `json:"subject_types_supported,omitempty"`

	AuthorizationEncryptionAlgValuesSupported []string `json:"authorization_encryption_alg_values_supported,omitempty"`

	AuthorizationEncryptionEncValuesSupported []string `json:"authorization_encryption_enc_values_supported,omitempty"`

	AuthorizationSigningAlgValuesSupported []string `json:"authorization_signing_alg_values_supported,omitempty"`

	// IDTokenSigningAlgValuesSupported contains a list of JWS signing algorithms (alg values) supported by the OP for the ID Token.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`

	// IDTokenEncryptionAlgValuesSupported contains a list of JWE encryption algorithms (alg values) supported by the OP for the ID Token.
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported,omitempty"`

	// IDTokenEncryptionEncValuesSupported contains a list of JWE encryption algorithms (enc values) supported by the OP for the ID Token.
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported,omitempty"`

	// UserinfoSigningAlgValuesSupported contains a list of JWS signing algorithms (alg values) supported by the OP for UserInfo Endpoint.
	UserinfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported,omitempty"`

	// UserinfoEncryptionAlgValuesSupported contains a list of JWE encryption algorithms (alg values) supported by the OP for the UserInfo Endpoint.
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`

	// UserinfoEncryptionEncValuesSupported contains a list of JWE encryption algorithms (enc values) supported by the OP for the UserInfo Endpoint.
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`

	// RequestObjectSigningAlgValuesSupported contains a list of JWS signing algorithms (alg values) supported by the OP for Request Objects.
	// These algorithms are used both then the Request Object is passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter).
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`

	// RequestObjectEncryptionAlgValuesSupported contains a list of JWE encryption algorithms (alg values) supported by the OP for Request Objects.
	// These algorithms are used both when the Request Object is passed by value and by reference.
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`

	// RequestObjectEncryptionEncValuesSupported contains a list of JWE encryption algorithms (enc values) supported by the OP for Request Objects.
	// These algorithms are used both when the Request Object is passed by value and by reference.
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported contains a list of Client Authentication methods supported by the Token Endpoint. If omitted, the default is client_secret_basic.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// TokenEndpointAuthSigningAlgValuesSupported contains a list of JWS signing algorithms (alg values) supported by the Token Endpoint
	// for the signature of the JWT used to authenticate the Client by private_key_jwt and client_secret_jwt.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// RevocationEndpointAuthMethodsSupported contains a list of Client Authentication methods supported by the Revocation Endpoint. If omitted, the default is client_secret_basic.
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`

	// RevocationEndpointAuthSigningAlgValuesSupported contains a list of JWS signing algorithms (alg values) supported by the Revocation Endpoint
	// for the signature of the JWT used to authenticate the Client by private_key_jwt and client_secret_jwt.
	RevocationEndpointAuthSigningAlgValuesSupported []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`

	// IntrospectionEndpointAuthMethodsSupported contains a list of Client Authentication methods supported by the Introspection Endpoint.
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`

	// IntrospectionEndpointAuthSigningAlgValuesSupported contains a list of JWS signing algorithms (alg values) supported by the Revocation Endpoint
	// for the signature of the JWT used to authenticate the Client by private_key_jwt and client_secret_jwt.
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`

	// ClaimTypesSupported contains a list of Claim Types that the OP supports (normal, aggregated, distributed). If omitted, the default is normal Claims.
	ClaimTypesSupported []string `json:"claim_types_supported,omitempty"`

	// ClaimsSupported contains a list of Claim Names the OP may be able to supply values for. This list might not be exhaustive.
	ClaimsSupported []string `json:"claims_supported,omitempty"`

	// ClaimsParameterSupported specifies whether the OP supports use of the `claims` parameter. If omitted, the default is false.
	ClaimsParameterSupported bool `json:"claims_parameter_supported,omitempty"`

	// CodeChallengeMethodsSupported contains a list of Proof Key for Code Exchange (PKCE) code challenge methods supported by the OP.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`

	// ClaimsLocalesSupported contains a list of BCP47 language tag values that the OP supports for values of Claims returned.
	ClaimsLocalesSupported []string `json:"claims_locales_supported,omitempty"`

	// UILocalesSupported contains a list of BCP47 language tag values that the OP supports for the user interface.
	UILocalesSupported []string `json:"ui_locales_supported,omitempty"`

	// RequestParameterSupported specifies whether the OP supports use of the `request` parameter. If omitted, the default value is false.
	RequestParameterSupported bool `json:"request_parameter_supported,omitempty"`

	// RequestURIParameterSupported specifies whether the OP supports use of the `request_uri` parameter. If omitted, the default value is true. (therefore no omitempty)
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`

	// RequireRequestURIRegistration specifies whether the OP requires any `request_uri` to be pre-registered using the request_uris registration parameter. If omitted, the default value is false.
	RequireRequestURIRegistration bool `json:"require_request_uri_registration,omitempty"`

	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens,omitempty"`

	// BackChannelLogoutSupported specifies whether the OP supports back-channel logout (https://openid.net/specs/openid-connect-backchannel-1_0.html),
	// with true indicating support. If omitted, the default value is false.
	BackChannelLogoutSupported bool `json:"backchannel_logout_supported,omitempty"`

	// BackChannelLogoutSessionSupported specifies whether the OP can pass a sid (session ID) Claim in the Logout Token to identify the RP session with the OP.
	// If supported, the sid Claim is also included in ID Tokens issued by the OP. If omitted, the default value is false.
	BackChannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported,omitempty"`

	// Extra contains the properties that are in the discovered configuration that isn't well known.
	Extra map[string]interface{} `json:"-"`
}

type MTLSEndpointAliases struct {
	// TokenEndpoint is the URL of the OAuth 2.0 Token Endpoint where all tokens are issued, except when using Implicit Flow
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// IntrospectionEndpoint is the URL of the OAuth 2.0 Introspection Endpoint.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// RevocationEndpoint is the URL of the OAuth 2.0 Revocation Endpoint.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
}
