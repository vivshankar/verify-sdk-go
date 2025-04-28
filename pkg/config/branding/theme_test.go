package branding_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/ibm-verify/verify-sdk-go/internal/test_helper"
	"github.com/ibm-verify/verify-sdk-go/pkg/auth"
	"github.com/ibm-verify/verify-sdk-go/pkg/config/branding"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	"github.com/ibm-verify/verify-sdk-go/x/logx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ThemeTestSuite struct {
	suite.Suite

	ctx     context.Context
	vctx    *contextx.VerifyContext
	themeID string
	client  *branding.ThemeClient
}

func (s *ThemeTestSuite) SetupTest() {
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
	s.themeID = os.Getenv("THEME_ID")
	require.NotEmpty(s.T(), s.themeID, "invalid config: THEME_ID is missing")

	s.client = branding.NewThemeClient()
}

func (s *ThemeTestSuite) TestFileDownloadUpload() {
	templatePath := "authentication/oidc/consent/default/user_consent.html"
	buf, _, err := s.client.GetFile(s.ctx, s.themeID, templatePath)
	require.NoError(s.T(), err, "unable to get file for theme %s; err=%v", s.themeID, err)

	originalBuffer := new(bytes.Buffer)
	_, err = originalBuffer.Write(buf)
	require.NoError(s.T(), err, "unable to make a copy of the buffer; err=%v", err)

	buffer := bytes.NewBuffer(buf)
	_, err = buffer.WriteString("<!-- This is part of the test -->")
	require.NoError(s.T(), err, "unable to add to the buffer; err=%v", err)

	err = s.client.UpdateFile(s.ctx, s.themeID, templatePath, buffer.Bytes())
	require.NoError(s.T(), err, "unable to update file; err=%v", err)

	buf, _, err = s.client.GetFile(s.ctx, s.themeID, templatePath)
	require.NoError(s.T(), err, "unable to get file after upload for theme %s; err=%v", s.themeID, err)
	assert.EqualValues(s.T(), len(buf), buffer.Len(), "buffer length does not match the downloaded file")

	err = s.client.UpdateFile(s.ctx, s.themeID, templatePath, originalBuffer.Bytes())
	require.NoError(s.T(), err, "unable to update file with the original buffer; err=%v", err)
}

func TestThemeTestSuite(t *testing.T) {
	suite.Run(t, new(ThemeTestSuite))
}
