package security_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/ibm-verify/verify-sdk-go/internal/test_helper"
	"github.com/ibm-verify/verify-sdk-go/pkg/auth"
	"github.com/ibm-verify/verify-sdk-go/pkg/config/security"
	"gopkg.in/yaml.v3"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	"github.com/ibm-verify/verify-sdk-go/x/logx"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type APIClientTestSuite struct {
	suite.Suite

	ctx                    context.Context
	vctx                   *contextx.VerifyContext
	APIClientName          string
	client                 *security.ApiClient
	apiClientCreateOrPatch security.APIClientConfig
}

func (s *APIClientTestSuite) SetupTest() {
	// initialize the logger
	contextID := uuid.NewString()
	logger := logx.NewLoggerWithWriter(contextID, slog.LevelInfo, os.Stdout)
	logger.AddNewline = true

	// load common config
	tenant, clientID, clientSecret := test_helper.LoadCommonConfig(s.T())

	// get token
	client := &auth.Client{
		Tenant: tenant,
		ClientAuth: &auth.ClientSecretPost{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
	}

	tokenResponse, err := client.TokenWithAPIClient(context.Background(), nil)
	require.NoError(s.T(), err, "unable to get a token; err=%v", err)

	s.ctx, err = contextx.NewContextWithVerifyContext(context.Background(), logger)
	require.NoError(s.T(), err, "unable to get a new context")
	s.vctx = contextx.GetVerifyContext(s.ctx)
	s.vctx.Token = tokenResponse.AccessToken
	s.vctx.Tenant = tenant

	// load specific config
	s.APIClientName = os.Getenv("API_CLIENT_NAME")
	require.NotEmpty(s.T(), s.APIClientName, "invalid config: API_CLIENT_NAME is missing")
	// api client details for creation

	apiCleintCreateRawData := `
clientName: TestClientSabuj
description: custom TestClientSabuj descriptionn
entitlements:
  - analyticsDataSyncToCloud
  - analyticsSatelliteOnboard
  - readCerts
  - readAPIClients
  - manageIdentitySources
  - readIdentitySources
  - manageMFAMethods
  - readMFAMethods
  - manageEnrollMFAMethodAnyUser
  - readEnrollMFAMethodAnyUser
  - authnAnyUser
  - manageAuthenticatorsConfig    
enabled: true
overrideSettings:
  restrictScopes: false
  scopes: []
additionalConfig:
  clientAuthMethod: default
  validateClientAssertionJti: true
idTokenSigningAlg: none
`

	_ = yaml.Unmarshal([]byte(apiCleintCreateRawData), &s.apiClientCreateOrPatch)

	apiCleintPatchRawData := `
clientName: TestClientSabuj
description: custom TestClientSabuj1122 descriptionn
entitlements:
  - analyticsDataSyncToCloud
  - analyticsSatelliteOnboard
  - readCerts
  - readAPIClients
  - manageIdentitySources
  - readIdentitySources
  - manageMFAMethods
  - readMFAMethods
  - manageEnrollMFAMethodAnyUser
  - readEnrollMFAMethodAnyUser
  - authnAnyUser
  - manageAuthenticatorsConfig    
enabled: true
overrideSettings:
  restrictScopes: false
  scopes: []
additionalConfig:
  clientAuthMethod: default
  validateClientAssertionJti: true
idTokenSigningAlg: none
`
	_ = yaml.Unmarshal([]byte(apiCleintPatchRawData), &s.apiClientCreateOrPatch)

	s.client = security.NewAPIClient()
}

func (s *APIClientTestSuite) TestAPIClient() {
	var err error
	// Create API Client
	_, err = s.client.CreateAPIClient(s.ctx, &s.apiClientCreateOrPatch)
	require.NoError(s.T(), err, "unable to create API Client %s; err=%v", s.APIClientName, err)

	// Get API Client details
	_, _, err = s.client.GetAPIClient(s.ctx, s.APIClientName)
	require.NoError(s.T(), err, "unable to get API Client %s; err=%v", s.APIClientName, err)

	// Get API Client list
	_, _, err = s.client.GetAPIClients(s.ctx, "", "", 0, 0)
	require.NoError(s.T(), err, "unable to list API Clients; err=%v", err)

	// Update API Client
	err = s.client.UpdateAPIClient(s.ctx, &s.apiClientCreateOrPatch)
	require.NoError(s.T(), err, "unable to update API Client %s; err=%v", s.APIClientName, err)

	// Delete API Client
	err = s.client.DeleteAPIClientById(s.ctx, s.APIClientName)
	require.NoError(s.T(), err, "unable to delete API Client %s; err=%v", s.APIClientName, err)
}

func TestAPIClientTestSuite(t *testing.T) {
	suite.Run(t, new(APIClientTestSuite))
}
