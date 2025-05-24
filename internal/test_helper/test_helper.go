package test_helper

import (
	"context"
	"os"
	"testing"

	"github.com/ibm-verify/verify-sdk-go/pkg/auth"
	"github.com/stretchr/testify/require"
)

func generateAccessToken(tenant string, clientID string, clientSecret string) (string, error) {
	// get token
	client := &auth.Client{
		Tenant: tenant,
		ClientAuth: &auth.ClientSecretPost{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
	}

	tokenResponse, err := client.TokenWithAPIClient(context.Background(), nil)
	if err != nil {
		return "", err
	}
	return tokenResponse.AccessToken, nil
}

func LoadCommonConfig(t *testing.T) (string, string) {
	// load common config
	var err error
	accessToken := os.Getenv("ACCESS_TOKEN")
	tenant := os.Getenv("TENANT")
	require.NotEmpty(t, tenant, "invalid config; TENANT is missing")
	if accessToken != "" {
		return tenant, accessToken
	} else {
		clientID := os.Getenv("CLIENT_ID")
		clientSecret := os.Getenv("CLIENT_SECRET")
		//check required config are present or not
		require.NotEmpty(t, clientID, "invalid config; CLIENT_ID is missing")
		require.NotEmpty(t, clientSecret, "invalid config; CLIENT_SECRET is missing")
		accessToken, err = generateAccessToken(tenant, clientID, clientSecret)
		if err != nil {
			require.NoError(t, err, "unable to get a token; err=%v", err)
		}
	}

	return tenant, accessToken
}
