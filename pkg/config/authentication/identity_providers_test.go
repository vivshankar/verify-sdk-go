package authentication_test

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ibm-verify/verify-sdk-go/internal/test_helper"
	"github.com/ibm-verify/verify-sdk-go/pkg/config/authentication"
	"gopkg.in/yaml.v3"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	"github.com/ibm-verify/verify-sdk-go/pkg/core/models"
	"github.com/ibm-verify/verify-sdk-go/x/logx"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type IdentityProvidersTestSuite struct {
	suite.Suite

	ctx                    context.Context
	vctx                   *contextx.VerifyContext
	client                 *authentication.IdentitySourceClient
	identityProviderCreate *models.IdentitySource
	identityProviderPatch  *models.IdentitySource
}

func (s *IdentityProvidersTestSuite) SetupSuite() {
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

	// Identity Provider details for creation
	identityProviderCreateRawData := `
enabled: true
instanceName: TestIdentityProvider
properties:
- key: realm
  sensitive: false
  value: www.google.com
- key: identityLinkingEnabled
  sensitive: false
  value: 'true'
- key: principalAttribute
  sensitive: false
  value: email
- key: jitEnabled
  sensitive: false
  value: 'true'
- key: webEnabled
  sensitive: false
  value: 'false'
- key: scopes
  sensitive: false
  value: openid email profile https://www.googleapis.com/auth/user.phonenumbers.read
- key: client_secret
  sensitive: false
  value: secret
- key: client_id
  sensitive: false
  value: id
sourceTypeId: 3
`

	_ = yaml.Unmarshal([]byte(identityProviderCreateRawData), &s.identityProviderCreate)

	identityProviderPatchRawData := `
enabled: true
instanceName: TestIdentityProvider
properties:
- key: realm
  sensitive: false
  value: www.abc.com
- key: identityLinkingEnabled
  sensitive: false
  value: 'true'
- key: principalAttribute
  sensitive: false
  value: email
- key: jitEnabled
  sensitive: false
  value: 'true'
- key: webEnabled
  sensitive: false
  value: 'false'
- key: scopes
  sensitive: false
  value: openid email profile https://www.googleapis.com/auth/user.phonenumbers.read
- key: client_secret
  sensitive: false
  value: updatedsecret
- key: client_id
  sensitive: false
  value: updatedid
sourceTypeId: 8
`
	_ = yaml.Unmarshal([]byte(identityProviderPatchRawData), &s.identityProviderPatch)

	s.client = authentication.NewIdentitySourceClient()

	// clean up the identity sources if found
	if list, err := s.client.GetIdentitySources(s.ctx, &models.GetInstancesV2Params{
		Search: "instanceName = \"TestIdentityProvider\"",
		Filter: "enduser",
		Count:  1,
	}); err == nil && list.Total > 0 {
		_ = s.client.DeleteIdentitySource(s.ctx, list.IdentitySources[0].ID)
	}
}

func (s *IdentityProvidersTestSuite) TestIdentityProviders() {
	var err error
	// Create Identity Provider
	resp, err := s.client.CreateIdentitySource(s.ctx, s.identityProviderCreate)
	require.NoError(s.T(), err, "unable to create Identity Provider; err=%v", err)
	// extract the ID from the response
	identitySourceID := strings.Split(resp, "/")[len(strings.Split(resp, "/"))-1]

	// Get Identity Provider details
	_, err = s.client.GetIdentitySource(s.ctx, identitySourceID)
	require.NoError(s.T(), err, "unable to get Identity Provider %s; err=%v", identitySourceID, err)

	// Update Identity Provider
	err = s.client.UpdateIdentitySource(s.ctx, identitySourceID, s.identityProviderPatch)
	require.NoError(s.T(), err, "unable to update Identity Provider %s; err=%v", identitySourceID, err)

	// Delete Identity Provider
	err = s.client.DeleteIdentitySource(s.ctx, identitySourceID)
	require.NoError(s.T(), err, "unable to delete Identity Provider %s; err=%v", identitySourceID, err)
}

func TestIdentityProvidersTestSuite(t *testing.T) {
	suite.Run(t, new(IdentityProvidersTestSuite))
}
