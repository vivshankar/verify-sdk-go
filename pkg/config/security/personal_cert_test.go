package security_test

import (
	"context"
	"log/slog"
	"os"
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

type PersonalCertTestSuite struct {
	suite.Suite
	ctx        context.Context
	vctx       *contextx.VerifyContext
	certLabel  string
	client     *security.PersonalCertClient
	certCreate security.PersonalCert
}

func (s *PersonalCertTestSuite) SetupTest() {
	var err error
	// Initialize the logger
	contextID := uuid.NewString()
	logger := logx.NewLoggerWithWriter(contextID, slog.LevelInfo, os.Stdout)
	logger.AddNewline = true

	// Load common config
	tenant, accessToken := test_helper.LoadCommonConfig(s.T())

	s.ctx, err = contextx.NewContextWithVerifyContext(context.Background(), logger)
	require.NoError(s.T(), err, "unable to get a new context")

	s.vctx = contextx.GetVerifyContext(s.ctx)
	s.vctx.Token = accessToken
	s.vctx.Tenant = tenant

	// Load specific config
	s.certLabel = "TestCert"

	// Certificate details for creation (from provided YAML)
	certCreateRawData := `
label: TestCert
subject: "CN=IBM,OU=IBM,O=IBM,L=city,ST=state,C=country"
expire: 3650
keysize: 2048
signature_algorithm: "SHA256withRSA"
isDefault: false
cert: "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"
password: "Apollo01!"
`
	_ = yaml.Unmarshal([]byte(certCreateRawData), &s.certCreate)

	s.client = security.NewPersonalCertClient()
}

func (s *PersonalCertTestSuite) TestPersonalCert() {
	var err error

	// Create personal certificate
	_, err = s.client.CreatePersonalCert(s.ctx, &s.certCreate)
	require.NoError(s.T(), err, "unable to create personal certificate %s; err=%v", s.certLabel, err)

	// Get personal certificate details
	_, _, err = s.client.GetPersonalCert(s.ctx, s.certLabel)
	require.NoError(s.T(), err, "unable to get personal certificate %s; err=%v", s.certLabel, err)

	// Get personal certificates list
	_, _, err = s.client.GetPersonalCerts(s.ctx, "", "")
	require.NoError(s.T(), err, "unable to list personal certificates; err=%v", err)

	// Delete personal certificate
	err = s.client.DeletePersonalCert(s.ctx, s.certLabel)
	require.NoError(s.T(), err, "unable to delete personal certificate %s; err=%v", s.certLabel, err)
}

func TestPersonalCertTestSuite(t *testing.T) {
	suite.Run(t, new(PersonalCertTestSuite))
}
