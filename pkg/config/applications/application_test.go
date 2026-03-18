package applications_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ibm-verify/verify-sdk-go/internal/test_helper"
	"github.com/ibm-verify/verify-sdk-go/pkg/config/applications"
	"github.com/ibm-verify/verify-sdk-go/pkg/core/models"
	"gopkg.in/yaml.v3"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	"github.com/ibm-verify/verify-sdk-go/x/logx"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ApplicationTestSuite struct {
	suite.Suite

	ctx               context.Context
	vctx              *contextx.VerifyContext
	client            *applications.ApplicationClient
	applicationCreate *models.ApplicationSettings
	applicationPatch  *models.ApplicationSettings
}

func (s *ApplicationTestSuite) SetupTest() {
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

	// application details for creation
	applicationCreateRawData := `
name: TestApplication
templateId: '669'
applicationState: true
description: IBM Verify application description//
visibleOnLaunchpad: true
providers:
  sso:
    domainName: aclc-target-fed-prod-us01b.verify.ibmforusgov.com
    userOptions: applicationBookmark
  saml:
    properties:
      companyName: IBM
  bookmark:
    bookmarkUrl: https://aclc-prov-fed-prod-us01b.verify.ibmforusgov.com
provisioning:
  extension:
    properties:
      endpointBaseUrl: aclc-target-fed-prod-us01b.verify.ibmforusgov.com
  attributeMappings:
  - targetName: userName
    sourceId: '1'
    outboundTracking: false
  - targetName: emails[0].value
    sourceId: '3'
    outboundTracking: false
  - targetName: name.givenName
    sourceId: '6'
    outboundTracking: false
  - targetName: name.familyName
    sourceId: '7'
    outboundTracking: false
  - targetName: phoneNumbers[0].value
    sourceId: '8'
    outboundTracking: false
  - targetName: department
    sourceId: '11'
    outboundTracking: false
  policies:
    provPolicy: automatic
    deProvPolicy: automatic
    deProvAction: delete
    gracePeriod: 0
  sendNotifications: true
  reverseAttributeMappings: []
  authentication:
    properties:
      pwd_client_secret: pKbnD2PUc7
      client_id: efa84c79-8265-4dd9-b785-10dba85de09d
  provisioningState: ''
apiAccessClients:
- accessTokenLifetime: 7200
  accessTokenType: default
  clientName: my custom policy testinggg2
  enabled: true
  jwtSigningAlg: RS256
  restrictScopes: false
  scopes: []
  defaultEntitlements:
  - authnAnyUser
  additionalConfig:
    clientAuthMethod: client_secret_basic
`

	_ = yaml.Unmarshal([]byte(applicationCreateRawData), &s.applicationCreate)

	applicationPatchRawData := `
name: TestApplication
templateId: '669'
applicationState: true
description: IBM Verify application updated description
visibleOnLaunchpad: true
providers:
  sso:
    domainName: aclc-target-fed-prod-us01b.verify.ibmforusgov.com
    userOptions: applicationBookmark
    spssoUrl: ''
    targetUrl: ''
    idpInitiatedSSOSupport: 'false'
  saml:
    justInTimeProvisioning: 'false'
    properties:
      companyName: IBM
    assertionConsumerService: []
    singleLogoutService: []
    additionalProperties: []
    manageNameIDService:
      url: ''
  bookmark:
    bookmarkUrl: https://aclc-prov-fed-prod-us01b.verify.ibmforusgov.com
  oidc:
    properties:
      grantTypes:
        authorizationCode: false
        implicit: false
        deviceFlow: false
        ropc: false
        jwtBearer: false
        policyAuth: false
        clientCredentials: false
        tokenExchange: false
      redirectUris: []
      idTokenSigningAlg: ''
      accessTokenExpiry: 0
      refreshTokenExpiry: 0
      doNotGenerateClientSecret: ''
      generateRefreshToken: ''
      renewRefreshTokenExpiry: 0
      signIdToken: ''
      signingCertificate: ''
      clientId: ''
      clientSecret: ''
      sendAllKnownUserAttributes: ''
      jwksUri: ''
      consentType: ''
      renewRefreshToken: ''
      idTokenEncryptAlg: ''
      idTokenEncryptEnc: ''
      idTokenEncryptKey: ''
    grantProperties:
      generateDeviceFlowQRCode: ''
    token:
      accessTokenType: ''
      audiences: []
      attributeMappings: []
    jwtBearerProperties:
      userIdentifier: ''
      identitySource: ''
    applicationUrl: ''
    restrictScopes: ''
    scopes: []
    entitlements: []
    restrictEntitlements: false
    consentAction: ''
    requirePkceVerification: ''
  wsfed:
    properties:
      activeProfile:
        defaultRealm: ''
      signingSettings:
        signSamlAssertion: ''
        keyLabel: ''
        signatureAlgorithm: ''
      callbackURL: ''
      providerId: ''
      multipleDomainsEnabled: ''
      ici_reserved_subjectNameID: ''
      additionalProperties: []
provisioning:
  extension:
    properties:
      endpointBaseUrl: aclc-target-fed-prod-us01b.verify.ibmforusgov.com
  attributeMappings:
  - targetName: userName
    sourceId: '1'
    outboundTracking: false
  - targetName: emails[0].value
    sourceId: '3'
    outboundTracking: false
  - targetName: name.givenName
    sourceId: '6'
    outboundTracking: false
  - targetName: name.familyName
    sourceId: '7'
    outboundTracking: false
  - targetName: phoneNumbers[0].value
    sourceId: '8'
    outboundTracking: false
  - targetName: department
    sourceId: '11'
    outboundTracking: false
  policies:
    provPolicy: automatic
    deProvPolicy: automatic
    deProvAction: delete
    gracePeriod: 0
  sendNotifications: true
  reverseAttributeMappings: []
  authentication:
    properties:
      pwd_client_secret: pKbnD2PUc7
      client_id: efa84c79-8265-4dd9-b785-10dba85de09d
  provisioningState: ''
apiAccessClients:
- accessTokenLifetime: 7200
  accessTokenType: default
  clientName: my custom policy testinggg2
  enabled: true
  jwtSigningAlg: RS256
  restrictScopes: false
  scopes: []
  defaultEntitlements:
  - authnAnyUser
  additionalConfig:
    clientAuthMethod: client_secret_basic
`
	_ = yaml.Unmarshal([]byte(applicationPatchRawData), &s.applicationPatch)

	s.client = applications.NewApplicationClient()

	// delete the applications if found
	criteria := &models.SearchApplicationsParams{
		Search: fmt.Sprintf("q=%s", s.applicationCreate.Name),
		Limit:  "1",
		Page:   "1",
	}
	if apps, err := s.client.GetApplications(s.ctx, criteria); err == nil && apps.UnderscoreEmbedded != nil && apps.UnderscoreEmbedded.Applications != nil {

		for _, v := range apps.UnderscoreEmbedded.Applications {
			appID := v.UnderscoreLinks.Self.Href[strings.LastIndex(v.UnderscoreLinks.Self.Href, "/")+1:]
			logger.Infof("Deleting application with ID: %s", appID)
			_ = s.client.DeleteApplication(s.ctx, appID)
		}
	}
}

func (s *ApplicationTestSuite) TestApplication() {
	var err error
	// Create Application
	resp, err := s.client.CreateApplication(s.ctx, s.applicationCreate)
	require.NoError(s.T(), err, "unable to create Application ; err=%v", err)
	// set the access policy ID
	applicationID := strings.Split(resp, "/")[len(strings.Split(resp, "/"))-1]

	// Get Application details
	_, err = s.client.GetApplication(s.ctx, applicationID)
	require.NoError(s.T(), err, "unable to get Application %s; err=%v", applicationID, err)

	// Update Application
	for {
		err = s.client.UpdateApplication(s.ctx, applicationID, s.applicationPatch)
		if err != nil {
			if strings.Contains(err.Error(), "code=206") {
				fmt.Println("===============================================================")
				fmt.Println("Retrying Update in 5 seconds, as creation still in progress.....")
				fmt.Println("===============================================================")
				time.Sleep(5 * time.Second)
				continue
			} else {
				break
			}
		} else {
			break
		}
	}
	require.NoError(s.T(), err, "unable to update Application %s; err=%v", applicationID, err)

	// Delete Application
	err = s.client.DeleteApplication(s.ctx, applicationID)
	require.NoError(s.T(), err, "unable to delete Application %s; err=%v", applicationID, err)
}

func TestApplicationTestSuite(t *testing.T) {
	suite.Run(t, new(ApplicationTestSuite))
}
