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

type SignerCertTestSuite struct {
	suite.Suite
	ctx        context.Context
	vctx       *contextx.VerifyContext
	certLabel  string
	client     *security.SignerCertClient
	certCreate security.SignerCert
}

func (s *SignerCertTestSuite) SetupTest() {
	// Initialize the logger
	contextID := uuid.NewString()
	logger := logx.NewLoggerWithWriter(contextID, slog.LevelInfo, os.Stdout)
	logger.AddNewline = true

	// Load common config
	tenant, clientID, clientSecret := test_helper.LoadCommonConfig(s.T())

	// Get token
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

	// Load specific config
	s.certLabel = os.Getenv("SIGNER_CERT_LABEL")
	require.NotEmpty(s.T(), s.certLabel, "invalid config: SIGNER_CERT_LABEL is missing")

	// Certificate details for creation (from provided YAML)
	certCreateRawData := `
label: testfile3
cert: "MIIC9TCCAd2gAwIBAgIQc2E2YHRpYahIjQkaW61IfjANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhkZWxpbmVhMTAeFw0yNTA1MDEwNzAwMzhaFw0zMDA1MDEwNzAwMzhaMBMxETAPBgNVBAMMCGRlbGluZWExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu8dAVsvVcWv7rGoXckwPKvmE27n/qIf7/hLZXTfK9D5QVenxNDjqglmDYm8hL6Gxo9jzqS9Wc2LSNqRHVnsKG9NozKDciiJiZVmhPEqwCYlQl0yz1L7/M6xblkXq1zCoqA/MQu4u5QtCXTL16MO7iGQW0uajt3VVQ6yRjNR/nCRufHGfcLQSofZE5tx9s6LbDCmLG7+3ApukrkGDZeXQIx0vI5kuKCC05DJhqgXy103JqsRX2L87JdOlokqI4OX6oKcFbV6kPhexVkhEV/HSUHV2Hkxk7MPF9yqUwPVJwPEWdqUzFJKr6iUhecVBX3Nz8kwT8n3t5GSg1H/tAMR/FQIDAQABo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUOkKru8ucxJojACa+rhMjirgyH1AwDQYJKoZIhvcNAQELBQADggEBAKocFw7+evHwIKC0AC7EAzvs0oq2QKpySTfaRTv0b40VvehGTlSIWP0Fisok3Vwc6Ivuz66RraP6IsL4QmMuqLTIsh973fimaW0Nl0wooyaSP+9iSmG9E11+Xb4v6yADFlEaVIDpp8oXzz1OyNotBiCEWymEDdkfx4ErugWodjBoG0Y3UAKZbH+GbwIbd/6VOOhGkM8om8txgK0+PJGy5pZUTxUd+30iJ6vS2hgPbquYgPb9B7YdH30XCnds+wm1uyS3hsXZnbKXGGeEAYCh6TM/rx0Jb9Zna7QRQypPKU8RluAMg1So9D4YxWHHjmULp0TRdc1TUUHof+fZnQqGK8U="
`
	_ = yaml.Unmarshal([]byte(certCreateRawData), &s.certCreate)

	s.client = security.NewSignerCertClient()
}

func (s *SignerCertTestSuite) TestSignerCert() {
	var err error

	// Create signer certificate
	_, err = s.client.CreateSignerCert(s.ctx, &s.certCreate)
	require.NoError(s.T(), err, "unable to create signer certificate %s; err=%v", s.certLabel, err)

	// Get signer certificate details
	_, _, err = s.client.GetSignerCert(s.ctx, s.certLabel)
	require.NoError(s.T(), err, "unable to get signer certificate %s; err=%v", s.certLabel, err)

	// Get signer certificates list
	_, _, err = s.client.GetSignerCerts(s.ctx, "", "")
	require.NoError(s.T(), err, "unable to list signer certificates; err=%v", err)

	// Delete signer certificate
	err = s.client.DeleteSignerCert(s.ctx, s.certLabel)
	require.NoError(s.T(), err, "unable to delete signer certificate %s; err=%v", s.certLabel, err)
}

func TestSignerCertTestSuite(t *testing.T) {
	suite.Run(t, new(SignerCertTestSuite))
}
