package security_test

import (
	"context"
	"log/slog"
	"os"
	"strconv"
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

type AccessPolicyTestSuite struct {
	suite.Suite

	ctx                       context.Context
	vctx                      *contextx.VerifyContext
	client                    *security.PolicyClient
	accessPolicyCreateOrPatch security.Policy
}

func (s *AccessPolicyTestSuite) SetupTest() {
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

	// Access Policy details for creation
	accessPolicyCreateRawData := `
name: TestPolicy
description: custom access policy
containsFirstFactor: true
rules:
  - name: My rule
    description: My rule
    alwaysRun: true
    firstFactor: false
    conditions:
      - type: location
        attributes:
          - name: country
            opCode: IN
            values:
              - US
    result:
      action: ACTION_DENY
      serverSideActions:
        - actionId: "sampleActionId"
          version: "1.0"
      authnMethods:
        - "questions"
        - "smsotp"
  - name: My second rule 
    description: My second rule 
    alwaysRun: true
    firstFactor: false
    conditions:
      - type: location
        attributes:
          - name: country
            opCode: NOTIN
            values:
              - UK
    result:
      action: ACTION_DENY
      serverSideActions:
        - actionId: "sampleActionId"
          version: "1.0"
      authnMethods:
        - "questions"
        - "smsotp"
  - name: test
    description: 'my test rule'
    alwaysRun: false
    firstFactor: false
    conditions:
    - opCode: MATCH
      values:
      - "127.0.0.2"
      type: ipAddress
    result:
      action: ACTION_MFA_ALWAYS
      serverSideActions: []
      authnMethods:
      - urn:ibm:security:authentication:asf:macotp
meta:
  state: ACTIVE
  schema: urn:access:policy:5.0:schema
  label: Initial revision
  scope:
    - "administrators"
  enforcementType: fedSSO
  evaluationContext: '{"landing":"12345665"}'
  tenantDefaultPolicy: false
validations:
  subscriptionsNeeded:
    - "string"
`

	_ = yaml.Unmarshal([]byte(accessPolicyCreateRawData), &s.accessPolicyCreateOrPatch)

	accessPolicyPatchRawData := `
name: TestPolicy
description: Updated TestPolicy
containsFirstFactor: true
rules:
  - name: My rule
    description: My rule
    alwaysRun: true
    firstFactor: false
    conditions:
      - type: location
        attributes:
          - name: country
            opCode: IN
            values:
              - US
    result:
      action: ACTION_DENY
      serverSideActions:
        - actionId: "sampleActionId"
          version: "1.0"
      authnMethods:
        - "questions"
        - "smsotp"
  - name: My second rule 
    description: My second rule 
    alwaysRun: true
    firstFactor: false
    conditions:
      - type: location
        attributes:
          - name: country
            opCode: NOTIN
            values:
              - UK
    result:
      action: ACTION_DENY
      serverSideActions:
        - actionId: "sampleActionId"
          version: "1.0"
      authnMethods:
        - "questions"
        - "smsotp"
  - name: test
    description: 'my test rule'
    alwaysRun: false
    firstFactor: false
    conditions:
    - opCode: MATCH
      values:
      - "127.0.0.2"
      type: ipAddress
    result:
      action: ACTION_MFA_ALWAYS
      serverSideActions: []
      authnMethods:
      - urn:ibm:security:authentication:asf:macotp
meta:
  state: ACTIVE
  schema: urn:access:policy:5.0:schema
  label: Initial revision
  scope:
    - "administrators"
  enforcementType: fedSSO
  evaluationContext: '{"landing":"12345665"}'
  tenantDefaultPolicy: false
validations:
  subscriptionsNeeded:
    - "string"
`
	_ = yaml.Unmarshal([]byte(accessPolicyPatchRawData), &s.accessPolicyCreateOrPatch)

	s.client = security.NewAccessPolicyClient()
}

func (s *AccessPolicyTestSuite) TestAccessPolicy() {
	var err error
	// Create Access Policy
	resp, err := s.client.CreateAccessPolicy(s.ctx, &s.accessPolicyCreateOrPatch)
	require.NoError(s.T(), err, "unable to create Access Policy; err=%v", err)
	// set the access policy ID
	policyID := strings.Split(resp, "/")[len(strings.Split(resp, "/"))-1]

	// Get Access Policy details
	_, _, err = s.client.GetAccessPolicy(s.ctx, policyID)
	require.NoError(s.T(), err, "unable to get Access Policy %s; err=%v", policyID, err)

	// Get Access Policy list
	_, _, err = s.client.GetAccessPolicies(s.ctx, 1, 1)
	require.NoError(s.T(), err, "unable to list Access Policies; err=%v", err)

	// Update Access Policy
	s.accessPolicyCreateOrPatch.ID, _ = strconv.Atoi(policyID)
	err = s.client.UpdateAccessPolicy(s.ctx, &s.accessPolicyCreateOrPatch)
	require.NoError(s.T(), err, "unable to update Access Policy %s; err=%v", policyID, err)

	// Delete Access Policy
	err = s.client.DeleteAccessPolicyByID(s.ctx, policyID)
	require.NoError(s.T(), err, "unable to delete Access Policy %s; err=%v", policyID, err)
}

func TestAccessPolicyTestSuite(t *testing.T) {
	suite.Run(t, new(AccessPolicyTestSuite))
}
