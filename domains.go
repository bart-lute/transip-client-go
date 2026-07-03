package transip_client_go

import (
	"net/http"

	"github.com/bart-lute/transip-client-go/models"
)

func (c *Client) Domains() (*[]models.Domain, error) {
	var domainsResponse models.DomainsResponse
	err := c.doRequest(http.MethodGet, "domains", nil, &domainsResponse)
	if err != nil {
		return nil, err
	}

	return &domainsResponse.Domains, nil
}
