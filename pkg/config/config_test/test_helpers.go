package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func LoadCommonConfig(t *testing.T) (string, string, string) {
	// load common config
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	tenant := os.Getenv("TENANT")

	//check required config are present or not
	require.NotEmpty(t, clientID, "invalid config; CLIENT_ID is missing")
	require.NotEmpty(t, clientSecret, "invalid config; CLIENT_SECRET is missing")
	require.NotEmpty(t, tenant, "invalid config; TENANT is missing")

	return tenant, clientID, clientSecret
}
