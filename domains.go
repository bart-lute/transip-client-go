package transip_client_go

import (
	"fmt"
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

func (c *Client) GetDNS(name string) (*[]models.DNS, error) {
	var dnsResponse models.DNSResponse
	err := c.doRequest(http.MethodGet, fmt.Sprintf("domains/%s/dns", name), nil, &dnsResponse)
	if err != nil {
		return nil, err
	}

	return &dnsResponse.DNSEntries, nil
}
