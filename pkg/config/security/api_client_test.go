package security_test

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ibm-verify/verify-sdk-go/internal/test_helper"
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
	client                 *security.APIClient
	apiClientCreateOrPatch security.APIClientConfig
}

func (s *APIClientTestSuite) SetupTest() {
	var err error
	// initialize the logger
	contextID := uuid.NewString()
	logger := logx.NewLoggerWithWriter(contextID, slog.LevelInfo, os.Stdout)
	logger.AddNewline = true

	// load common config
	tenant, accessToken := test_helper.LoadCommonConfig(s.T())

	s.ctx, err = contextx.NewContextWithVerifyContext(context.Background(), logger)
	require.NoError(s.T(), err, "unable to get a new context")
	s.vctx = contextx.GetVerifyContext(s.ctx)
	s.vctx.Token = accessToken
	s.vctx.Tenant = tenant

	// api client details for creation
	apiClientCreateRawData := `
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

	_ = yaml.Unmarshal([]byte(apiClientCreateRawData), &s.apiClientCreateOrPatch)

	apiClientPatchRawData := `
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
	_ = yaml.Unmarshal([]byte(apiClientPatchRawData), &s.apiClientCreateOrPatch)

	s.client = security.NewAPIClient()
}

func (s *APIClientTestSuite) TestAPIClient() {
	var err error
	// Create API Client
	resp, err := s.client.CreateAPIClient(s.ctx, &s.apiClientCreateOrPatch)
	require.NoError(s.T(), err, "unable to create API Client; err=%v", err)
	// set the API Client ID
	apiCleintID := strings.Split(resp, "/")[len(strings.Split(resp, "/"))-1]

	// Get API Client details
	_, _, err = s.client.GetAPIClientByID(s.ctx, apiCleintID)
	require.NoError(s.T(), err, "unable to get API Client; err=%v", err)

	// Get API Client list
	_, _, err = s.client.GetAPIClients(s.ctx, "", "", 0, 0)
	require.NoError(s.T(), err, "unable to list API Clients; err=%v", err)

	// Update API Client
	err = s.client.UpdateAPIClient(s.ctx, &s.apiClientCreateOrPatch)
	require.NoError(s.T(), err, "unable to update API Client; err=%v", err)

	// Delete API Client
	err = s.client.DeleteAPIClientById(s.ctx, apiCleintID)
	require.NoError(s.T(), err, "unable to delete API Client; err=%v", err)
}

func TestAPIClientTestSuite(t *testing.T) {
	suite.Run(t, new(APIClientTestSuite))
}
