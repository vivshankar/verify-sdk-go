package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	typesx "github.com/ibm-verify/verify-sdk-go/x/types"
	"gopkg.in/yaml.v2"
)

type PersonalCert struct {
	NotBefore          string `yaml:"notbefore" json:"notbefore"`
	Subject            string `yaml:"subject" json:"subject"`
	NotAfter           string `yaml:"notafter" json:"notafter"`
	SerialNumber       string `yaml:"serial_number" json:"serial_number"`
	Label              string `yaml:"label" json:"label"`
	Version            int    `yaml:"version" json:"version"`
	Issuer             string `yaml:"issuer" json:"issuer"`
	IsDefault          bool   `yaml:"isDefault" json:"isDefault"`
	KeySize            int    `yaml:"keysize,omitempty" json:"keysize,omitempty"`
	SignatureAlgorithm string `yaml:"signature_algorithm,omitempty" json:"signature_algorithm,omitempty"`
	Cert               string `yaml:"cert" json:"cert"`
	Expire             int    `yaml:"expire,omitempty" json:"expire,omitempty"`
	Password           string `yaml:"password" json:"password"`
}

type PersonalCertListResponse struct {
	PersonalCerts []PersonalCert `yaml:"Resources" json:"Resources"`
}

type PersonalCertClient struct {
	Client *http.Client
}

func NewPersonalCertClient() *PersonalCertClient {
	return &PersonalCertClient{}
}

func (c *PersonalCertClient) CreatePersonalCert(ctx context.Context, PersonalCert *PersonalCert) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	defaultErr := errorsx.G11NError("unable to create personal certificate")
	params := &openapi.PostPersonalCertParams{}
	headers := &openapi.Headers{
		Accept:      "application/json",
		ContentType: "application/json",
		Token:       vc.Token,
	}
	body, err := json.Marshal(PersonalCert)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the personal certificate; err=%v", err.Error())
		return "", defaultErr
	}
	resp, err := client.PostPersonalCertWithBodyWithResponse(ctx, params, "application/json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to create a personal certificate; err=%s", err.Error())
		return "", errorsx.G11NError("unable to create personal certificate")
	}
	if resp.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to create personal certificate"); err != nil {
			vc.Logger.Errorf("unable to create the personal certificate; err=%s", err.Error())
			return "", err
		}
		vc.Logger.Errorf("Failed to create personal certificate; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", errorsx.G11NError("failed to create personal certificate; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}
	m := map[string]interface{}{}
	resourceURI := ""
	if err := yaml.Unmarshal(resp.Body, &m); err != nil {
		vc.Logger.Warnf("unable to unmarshal the response body to get the 'id'")
		resourceURI = resp.HTTPResponse.Header.Get("Location")
	} else {
		id := typesx.Map(m).SafeString("id", "")
		resourceURI = fmt.Sprintf("%s/%s", resp.HTTPResponse.Request.URL.String(), id)
	}
	return resourceURI, nil
}

func (c *PersonalCertClient) UpdatePersonalCert(ctx context.Context, personalCert *PersonalCert) error {
	vc := contextx.GetVerifyContext(ctx)
	if personalCert == nil {
		vc.Logger.Errorf("personal certificate object is nil")
		return errorsx.G11NError("personal certificate object is nil")
	}

	_, _, err := c.GetPersonalCertLabel(ctx, personalCert.Label)
	if err != nil {
		vc.Logger.Errorf("unable to get the personal certificate label '%s'; err=%s", personalCert.Label, err.Error())
		return errorsx.G11NError("unable to get the personal certificate label '%s'; err=%s", personalCert.Label, err.Error())
	}

	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{
		Accept:      "application/json",
		ContentType: "application/json",
		Token:       vc.Token,
	}
	params := &openapi.UpdatePersonalCertParams{}
	body, err := json.Marshal(personalCert)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the update request; err=%v", err)
		return errorsx.G11NError("unable to marshal the update request; err=%v", err)
	}

	resp, err := client.UpdatePersonalCertWithBodyWithResponse(ctx, personalCert.Label, params, "application/json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to update the personal certificate; err=%s", err.Error())
		return errorsx.G11NError("unable to update the personal certificate; err=%s", err.Error())
	}

	if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to update personal certificate"); err != nil {
			vc.Logger.Errorf("unable to update the personal certificate; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("failed to update personal certificate; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("failed to update personal certificate; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *PersonalCertClient) DeletePersonalCert(ctx context.Context, Label string) error {
	vc := contextx.GetVerifyContext(ctx)
	if vc == nil {
		return errorsx.G11NError("verify context is nil")
	}
	_, _, err := c.GetPersonalCertLabel(ctx, Label)
	if err != nil {
		vc.Logger.Errorf("unable to get the personal certificate label '%s'; err=%s", Label, err.Error())
		return errorsx.G11NError("unable to get the personal certificate label '%s'; err=%s", Label, err.Error())
	}

	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	params := &openapi.DeletePersonalCertParams{}
	headers := &openapi.Headers{
		Token:       vc.Token,
		ContentType: "application/json",
	}
	resp, err := client.DeletePersonalCertWithResponse(ctx, Label, params, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete the personal certificate; err=%s", err.Error())
		return errorsx.G11NError("unable to delete the personal certificate; err=%s", err.Error())
	}

	if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to delete personal certificate"); err != nil {
			vc.Logger.Errorf("unable to delete the personal certificate; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("failed to delete personal certificate; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("failed to delete personal certificate; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *PersonalCertClient) GetPersonalCert(ctx context.Context, label string) (*PersonalCert, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	personalCert, uri, err := c.GetPersonalCertLabel(ctx, label)
	if err != nil {
		vc.Logger.Errorf("unable to get the personal certificate label; err=%s", err.Error())
		return nil, "", err
	}

	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	getCertParams := &openapi.GetPersonalCertParams{}
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.GetPersonalCertWithResponse(ctx, label, getCertParams, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get the personal certificate; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get personal certificate"); err != nil {
			vc.Logger.Errorf("unable to get the personal certificate; err=%s", err.Error())
			return nil, "", err
		}
		vc.Logger.Errorf("unable to get the personal certificate; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get the personal certificate")
	}

	var certResponse struct {
		Cert string `json:"cert"`
	}
	if err = json.Unmarshal(resp.Body, &certResponse); err != nil {
		vc.Logger.Errorf("unable to parse personal certificate response; err=%s", err.Error())
		return nil, "", errorsx.G11NError("unable to parse personal certificate response")
	}
	personalCert.Cert = certResponse.Cert

	return personalCert, uri, nil
}

func (c *PersonalCertClient) GetPersonalCerts(ctx context.Context, sort string, count string) (*PersonalCertListResponse, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	getCertsParams := &openapi.GetPersonalCertsParams{}
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.GetPersonalCertsWithResponse(ctx, getCertsParams, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get personal certificates; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get personal certificates"); err != nil {
			vc.Logger.Errorf("unable to get personal certificates; err=%s", err.Error())
			return nil, "", err
		}
		vc.Logger.Errorf("unable to get personal certificates; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get personal certificates")
	}

	var certs []PersonalCert
	if err := json.Unmarshal(resp.Body, &certs); err != nil {
		var certList PersonalCertListResponse
		if err := json.Unmarshal(resp.Body, &certList); err != nil {
			vc.Logger.Errorf("unable to parse personal certificates response; err=%s, body=%s", err.Error(), string(resp.Body))
			return nil, "", errorsx.G11NError("unable to parse personal certificates response: %w", err)
		}
		certs = certList.PersonalCerts
	}

	certList := &PersonalCertListResponse{
		PersonalCerts: certs,
	}

	return certList, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *PersonalCertClient) GetPersonalCertLabel(ctx context.Context, Label string) (*PersonalCert, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	getCertsParams := &openapi.GetPersonalCertsParams{}
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.GetPersonalCertsWithResponse(ctx, getCertsParams, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get personal certificates for label validation; err=%s", err.Error())
		return nil, "", errorsx.G11NError("unable to get personal certificate with label %s; err=%s", Label, err.Error())
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get personal certificates"); err != nil {
			vc.Logger.Errorf("unable to get personal certificates; err=%s", err.Error())
			return nil, "", err
		}
		vc.Logger.Errorf("unable to get personal certificates; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get personal certificates")
	}

	var certs []PersonalCert
	if err := json.Unmarshal(resp.Body, &certs); err != nil {
		var certList PersonalCertListResponse
		if err := json.Unmarshal(resp.Body, &certList); err != nil {
			vc.Logger.Errorf("unable to parse personal certificates response; err=%s, body=%s", err.Error(), string(resp.Body))
			return nil, "", errorsx.G11NError("unable to parse personal certificates response: %w", err)
		}
		certs = certList.PersonalCerts
	}

	for _, cert := range certs {
		if strings.EqualFold(cert.Label, Label) {
			return &cert, resp.HTTPResponse.Request.URL.String(), nil
		}
	}
	vc.Logger.Errorf("no personal certificate found with label %s", Label)
	return nil, "", errorsx.G11NError("no personal certificate found with label %s", Label)
}
