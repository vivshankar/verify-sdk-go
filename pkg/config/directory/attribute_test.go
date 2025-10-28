package directory_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/ibm-verify/verify-sdk-go/internal/test_helper"
	"github.com/ibm-verify/verify-sdk-go/pkg/config/directory"
	"gopkg.in/yaml.v3"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	"github.com/ibm-verify/verify-sdk-go/x/logx"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type AttributeTestSuite struct {
	suite.Suite

	ctx            context.Context
	vctx           *contextx.VerifyContext
	client         *directory.AttributeClient
	attributeName  string
	attributeID    string
	attributeData  directory.Attribute
	searchCriteria directory.AttributesSearchCriteria

	// Store tenant and token at the suite level to reuse across tests
	tenant      string
	accessToken string
}

func (s *AttributeTestSuite) SetupSuite() {
	var err error
	// initialize the logger
	contextID := uuid.NewString()
	logger := logx.NewLoggerWithWriter(contextID, slog.LevelInfo, os.Stdout)
	logger.AddNewline = true

	// load common config once for the entire test suite
	s.tenant, s.accessToken = test_helper.LoadCommonConfig(s.T())

	ctx, err := contextx.NewContextWithVerifyContext(context.Background(), logger)
	require.NoError(s.T(), err, "unable to get a new context")
	vctx := contextx.GetVerifyContext(ctx)
	vctx.Token = s.accessToken
	vctx.Tenant = s.tenant

	// Initialize client and search criteria to find and delete test attribute if it exists
	client := directory.NewAttributeClient()
	searchCriteria := directory.AttributesSearchCriteria{
		Search: `name="testAttribute"`,
		Sort:   "+name",
		Limit:  10,
		Page:   1,
	}

	// Search for the test attribute
	attributeList, err := client.GetAttributes(ctx, &searchCriteria)
	if err == nil && attributeList != nil && len(attributeList.Attributes) > 0 {
		// If test attribute exists, delete it
		for _, attr := range attributeList.Attributes {
			if attr.ID != "" {
				s.T().Logf("Found existing test attribute with ID %s, deleting it", attr.ID)
				err = client.DeleteAttribute(ctx, attr.ID)
				if err != nil {
					s.T().Logf("Warning: Failed to delete existing test attribute: %v", err)
				}
			}
		}
	}
}

func (s *AttributeTestSuite) SetupTest() {
	var err error
	// initialize the logger
	contextID := uuid.NewString()
	logger := logx.NewLoggerWithWriter(contextID, slog.LevelInfo, os.Stdout)
	logger.AddNewline = true

	// Reuse the token and tenant from SetupSuite
	s.ctx, err = contextx.NewContextWithVerifyContext(context.Background(), logger)
	require.NoError(s.T(), err, "unable to get a new context")
	s.vctx = contextx.GetVerifyContext(s.ctx)
	s.vctx.Token = s.accessToken
	s.vctx.Tenant = s.tenant

	// load specific config
	s.attributeName = "testAttribute"

	// Initialize attribute data for creation
	attributeRawData := `
name: testAttribute
sourceType: static
description: Test attribute for unit testing
tags:
  - test
  - sdk
value: testValue
datatype: string
`
	_ = yaml.Unmarshal([]byte(attributeRawData), &s.attributeData)

	// Initialize search criteria
	s.searchCriteria = directory.AttributesSearchCriteria{
		Search: `name="testAttribute"`,
		Sort:   "+name",
		Limit:  10,
		Page:   1,
	}

	s.client = directory.NewAttributeClient()
}

func (s *AttributeTestSuite) TestGetAttribute() {
	// Create an attribute first
	resourceURI, err := s.client.CreateAttribute(s.ctx, &s.attributeData)
	require.NoError(s.T(), err, "unable to create attribute %s; err=%v", s.attributeName, err)
	require.NotEmpty(s.T(), resourceURI, "resource URI should not be empty")

	// Extract ID from resource URI
	s.attributeID = extractIDFromURI(resourceURI)
	require.NotEmpty(s.T(), s.attributeID, "attribute ID should not be empty")

	// Get attribute by ID
	attribute, uri, err := s.client.GetAttribute(s.ctx, s.attributeID)
	require.NoError(s.T(), err, "unable to get attribute %s; err=%v", s.attributeID, err)
	require.NotNil(s.T(), attribute, "attribute should not be nil")
	require.NotEmpty(s.T(), uri, "URI should not be empty")

	// Clean up - delete the attribute
	err = s.client.DeleteAttribute(s.ctx, s.attributeID)
	require.NoError(s.T(), err, "unable to delete attribute %s; err=%v", s.attributeID, err)
}

func (s *AttributeTestSuite) TestGetAttributes() {
	// Create an attribute first
	resourceURI, err := s.client.CreateAttribute(s.ctx, &s.attributeData)
	require.NoError(s.T(), err, "unable to create attribute %s; err=%v", s.attributeName, err)
	require.NotEmpty(s.T(), resourceURI, "resource URI should not be empty")

	// Extract ID from resource URI
	s.attributeID = extractIDFromURI(resourceURI)
	require.NotEmpty(s.T(), s.attributeID, "attribute ID should not be empty")

	// Get attributes with search criteria
	attributeList, err := s.client.GetAttributes(s.ctx, &s.searchCriteria)
	require.NoError(s.T(), err, "unable to get attributes; err=%v", err)
	require.NotNil(s.T(), attributeList, "attribute list should not be nil")

	// Get attributes without search criteria
	attributeList, err = s.client.GetAttributes(s.ctx, nil)
	require.NoError(s.T(), err, "unable to get attributes; err=%v", err)
	require.NotNil(s.T(), attributeList, "attribute list should not be nil")

	// Clean up - delete the attribute
	err = s.client.DeleteAttribute(s.ctx, s.attributeID)
	require.NoError(s.T(), err, "unable to delete attribute %s; err=%v", s.attributeID, err)
}

func (s *AttributeTestSuite) TestCreateAttribute() {
	// Create an attribute
	resourceURI, err := s.client.CreateAttribute(s.ctx, &s.attributeData)
	require.NoError(s.T(), err, "unable to create attribute %s; err=%v", s.attributeName, err)
	require.NotEmpty(s.T(), resourceURI, "resource URI should not be empty")

	// Extract ID from resource URI
	s.attributeID = extractIDFromURI(resourceURI)
	require.NotEmpty(s.T(), s.attributeID, "attribute ID should not be empty")

	// Clean up - delete the attribute
	err = s.client.DeleteAttribute(s.ctx, s.attributeID)
	require.NoError(s.T(), err, "unable to delete attribute %s; err=%v", s.attributeID, err)
}

func (s *AttributeTestSuite) TestUpdateAttribute() {
	// Create an attribute first
	resourceURI, err := s.client.CreateAttribute(s.ctx, &s.attributeData)
	require.NoError(s.T(), err, "unable to create attribute %s; err=%v", s.attributeName, err)
	require.NotEmpty(s.T(), resourceURI, "resource URI should not be empty")

	// Extract ID from resource URI
	s.attributeID = extractIDFromURI(resourceURI)
	require.NotEmpty(s.T(), s.attributeID, "attribute ID should not be empty")

	// Get attribute by ID
	attribute, _, err := s.client.GetAttribute(s.ctx, s.attributeID)
	require.NoError(s.T(), err, "unable to get attribute %s; err=%v", s.attributeID, err)

	// Update attribute
	attribute.ID = s.attributeID
	attribute.Description = "Updated description for testing"
	err = s.client.UpdateAttribute(s.ctx, attribute)
	require.NoError(s.T(), err, "unable to update attribute %s; err=%v", s.attributeID, err)

	// Verify update
	updatedAttribute, _, err := s.client.GetAttribute(s.ctx, s.attributeID)
	require.NoError(s.T(), err, "unable to get updated attribute %s; err=%v", s.attributeID, err)
	require.NotNil(s.T(), updatedAttribute.Description, "description should not be nil")
	require.Equal(s.T(), "Updated description for testing", updatedAttribute.Description, "description should be updated")

	// Clean up - delete the attribute
	err = s.client.DeleteAttribute(s.ctx, s.attributeID)
	require.NoError(s.T(), err, "unable to delete attribute %s; err=%v", s.attributeID, err)
}

func (s *AttributeTestSuite) TestDeleteAttribute() {
	// Create an attribute first
	resourceURI, err := s.client.CreateAttribute(s.ctx, &s.attributeData)
	require.NoError(s.T(), err, "unable to create attribute %s; err=%v", s.attributeName, err)
	require.NotEmpty(s.T(), resourceURI, "resource URI should not be empty")

	// Extract ID from resource URI
	s.attributeID = extractIDFromURI(resourceURI)
	require.NotEmpty(s.T(), s.attributeID, "attribute ID should not be empty")

	// Delete the attribute
	err = s.client.DeleteAttribute(s.ctx, s.attributeID)
	require.NoError(s.T(), err, "unable to delete attribute %s; err=%v", s.attributeID, err)

	// Verify deletion - should return error
	_, _, err = s.client.GetAttribute(s.ctx, s.attributeID)
	require.Error(s.T(), err, "attribute should be deleted")
}

// Helper function to extract ID from resource URI
func extractIDFromURI(uri string) string {
	// Simple implementation - in real code, you might want to use url.Parse or regex
	// This assumes the ID is the last part of the URI after the last slash
	if uri == "" {
		return ""
	}

	// Find the last slash and return everything after it
	for i := len(uri) - 1; i >= 0; i-- {
		if uri[i] == '/' {
			return uri[i+1:]
		}
	}

	return uri
}

func TestAttributeTestSuite(t *testing.T) {
	suite.Run(t, new(AttributeTestSuite))
}

// Made with Bob
