package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ibm-verify/verify-sdk-go/internal/openapi"
	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	typesx "github.com/ibm-verify/verify-sdk-go/x/types"
	"gopkg.in/yaml.v2"
)

type SignerCert struct {
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
}

type SignerCertListResponse struct {
	SignerCerts []SignerCert `yaml:"Resources" json:"Resources"`
}

type SignerCertClient struct {
	Client *http.Client
}

func NewSignerCertClient() *SignerCertClient {
	return &SignerCertClient{}
}

func (c *SignerCertClient) CreateSignerCert(ctx context.Context, SignerCert *SignerCert) (string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	defaultErr := errorsx.G11NError("unable to create Signer certificate")
	params := &openapi.ImportSignerCertParams{}
	headers := &openapi.Headers{
		Accept:      "application/json",
		ContentType: "application/json",
		Token:       vc.Token,
	}
	body, err := json.Marshal(SignerCert)
	if err != nil {
		vc.Logger.Errorf("unable to marshal the Signer certificate; err=%v", err.Error())
		return "", defaultErr
	}
	resp, err := client.ImportSignerCertWithBodyWithResponse(ctx, params, "application/json", bytes.NewBuffer(body), openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to create a Signer certificate; err=%s", err.Error())
		return "", errorsx.G11NError("unable to create Signer certificate")
	}
	if resp.StatusCode() != http.StatusCreated {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to create Signer certificate"); err != nil {
			vc.Logger.Errorf("unable to create the Signer certificate; err=%s", err.Error())
			return "", err
		}
		vc.Logger.Errorf("Failed to create Signer certificate; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return "", errorsx.G11NError("failed to create Signer certificate; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
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

func (c *SignerCertClient) DeleteSignerCert(ctx context.Context, Label string) error {
	vc := contextx.GetVerifyContext(ctx)
	if vc == nil {
		return errorsx.G11NError("verify context is nil")
	}
	_, _, err := c.GetSignerCertLabel(ctx, Label)
	if err != nil {
		vc.Logger.Errorf("unable to get the Signer certificate label '%s'; err=%s", Label, err.Error())
		return errorsx.G11NError("unable to get the Signer certificate label '%s'; err=%s", Label, err.Error())
	}

	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	params := &openapi.DeleteSignerCertParams{}
	headers := &openapi.Headers{
		Token:       vc.Token,
		ContentType: "application/json",
	}
	resp, err := client.DeleteSignerCertWithResponse(ctx, Label, params, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to delete the Signer certificate; err=%s", err.Error())
		return errorsx.G11NError("unable to delete the Signer certificate; err=%s", err.Error())
	}

	if resp.StatusCode() != http.StatusNoContent && resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to delete Signer certificate"); err != nil {
			vc.Logger.Errorf("unable to delete the Signer certificate; err=%s", err.Error())
			return err
		}
		vc.Logger.Errorf("failed to delete Signer certificate; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return errorsx.G11NError("failed to delete Signer certificate; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
	}

	return nil
}

func (c *SignerCertClient) GetSignerCerts(ctx context.Context, sort string, count string) (*SignerCertListResponse, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	getCertsParams := &openapi.GetSignerCertsParams{}
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.GetSignerCertsWithResponse(ctx, getCertsParams, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get Signer certificates; err=%s", err.Error())
		return nil, "", err
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get Signer certificates"); err != nil {
			vc.Logger.Errorf("unable to get Signer certificates; err=%s", err.Error())
			return nil, "", err
		}
		vc.Logger.Errorf("unable to get Signer certificates; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get Signer certificates")
	}

	var certs []SignerCert
	if err := json.Unmarshal(resp.Body, &certs); err != nil {
		var certList SignerCertListResponse
		if err := json.Unmarshal(resp.Body, &certList); err != nil {
			vc.Logger.Errorf("unable to parse Signer certificates response; err=%s, body=%s", err.Error(), string(resp.Body))
			return nil, "", errorsx.G11NError("unable to parse Signer certificates response: %w", err)
		}
		certs = certList.SignerCerts
	}

	certList := &SignerCertListResponse{
		SignerCerts: certs,
	}

	return certList, resp.HTTPResponse.Request.URL.String(), nil
}

func (c *SignerCertClient) GetSignerCertLabel(ctx context.Context, Label string) (*SignerCert, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	getCertsParams := &openapi.GetSignerCertsParams{}
	headers := &openapi.Headers{
		Token:  vc.Token,
		Accept: "application/json",
	}
	resp, err := client.GetSignerCertsWithResponse(ctx, getCertsParams, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get Signer certificates for label validation; err=%s", err.Error())
		return nil, "", errorsx.G11NError("unable to get Signer certificate with label %s; err=%s", Label, err.Error())
	}

	if resp.StatusCode() != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp.HTTPResponse, "unable to get Signer certificates"); err != nil {
			vc.Logger.Errorf("unable to get Signer certificates; err=%s", err.Error())
			return nil, "", err
		}
		vc.Logger.Errorf("unable to get Signer certificates; code=%d, body=%s", resp.StatusCode(), string(resp.Body))
		return nil, "", errorsx.G11NError("unable to get Signer certificates")
	}

	var certs []SignerCert
	if err := json.Unmarshal(resp.Body, &certs); err != nil {
		var certList SignerCertListResponse
		if err := json.Unmarshal(resp.Body, &certList); err != nil {
			vc.Logger.Errorf("unable to parse Signer certificates response; err=%s, body=%s", err.Error(), string(resp.Body))
			return nil, "", errorsx.G11NError("unable to parse Signer certificates response: %w", err)
		}
		certs = certList.SignerCerts
	}

	for _, cert := range certs {
		if strings.EqualFold(cert.Label, Label) {
			return &cert, resp.HTTPResponse.Request.URL.String(), nil
		}
	}
	vc.Logger.Errorf("no Signer certificate found with label %s", Label)
	return nil, "", errorsx.G11NError("no Signer certificate found with label %s", Label)
}

func (c *SignerCertClient) GetSignerCert(ctx context.Context, label string) (*SignerCert, string, error) {
	vc := contextx.GetVerifyContext(ctx)
	client := openapi.NewClientWithOptions(ctx, vc.Tenant, c.Client)
	headers := &openapi.Headers{Token: vc.Token, Accept: "application/json"}

	resp, err := client.GetSignerCert(ctx, label, &openapi.GetSignerCertParams{}, openapi.DefaultRequestEditors(ctx, headers)...)
	if err != nil {
		vc.Logger.Errorf("unable to get Signer certificate; err=%v", err)
		return nil, "", errorsx.G11NError("unable to get Signer certificate with label %s; err=%s", label, err.Error())
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if err := errorsx.HandleCommonErrors(ctx, resp, "unable to get Signer certificate"); err != nil {
			vc.Logger.Errorf("unable to get Signer certificate; err=%s", err.Error())
			return nil, "", err
		}
		return nil, "", errorsx.G11NError("unable to get Signer certificate; status code=%d", resp.StatusCode)
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		vc.Logger.Errorf("unable to read Signer certificate body; err=%v", err)
		return nil, "", errorsx.G11NError("unable to read Signer certificate body: %w", err)
	}

	var certResponse struct {
		Cert string `json:"cert"`
	}
	if err := json.Unmarshal(buf, &certResponse); err != nil || certResponse.Cert == "" {
		vc.Logger.Errorf("unable to parse Signer certificate; err=%v, body=%s", err, string(buf))
		return nil, "", errorsx.G11NError("unable to parse Signer certificate with label %s; err=%w", label, err)
	}

	signerCert := &SignerCert{
		Label: label,
		Cert:  certResponse.Cert,
	}

	if certsResp, err := client.GetSignerCertsWithResponse(ctx, &openapi.GetSignerCertsParams{}, openapi.DefaultRequestEditors(ctx, headers)...); err == nil && certsResp.StatusCode() == http.StatusOK {
		var certs []openapi.Certificate0
		if err := json.Unmarshal(certsResp.Body, &certs); err == nil {
			for _, c := range certs {
				if strings.EqualFold(c.Label, label) {
					*signerCert = SignerCert{
						NotBefore:          c.Notbefore,
						Subject:            c.Subject,
						NotAfter:           c.Notafter,
						SerialNumber:       c.SerialNumber,
						Label:              c.Label,
						Version:            int(c.Version),
						Issuer:             c.Issuer,
						KeySize:            int(c.Keysize),
						SignatureAlgorithm: c.SignatureAlgorithm,
						Cert:               certResponse.Cert,
					}
					break
				}
			}
		}
	}

	return signerCert, resp.Request.URL.String(), nil
}
