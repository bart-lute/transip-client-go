package models

type DomainsResponse struct {
	Domains []Domain `json:"domains"`
}

type Domain struct {
	Name               string       `json:"name"`
	Nameservers        []Nameserver `json:"nameservers"`
	Contacts           []Contact    `json:"contacts"`
	AuthCode           string       `json:"authCode"`
	IsTransferLocked   bool         `json:"isTransferLocked"`
	RegistrationDate   string       `json:"registrationDate"`
	RenewalDate        string       `json:"renewalDate"`
	IsWhitelabel       bool         `json:"isWhitelabel"`
	CancellationDate   string       `json:"cancellationDate"`
	CancellationStatus string       `json:"cancellationStatus"`
	IsDNSOnly          bool         `json:"isDnsOnly"`
	Tags               []string     `json:"tags"`
	CanEditDNS         bool         `json:"canEditDns"`
	HasAutoDNS         bool         `json:"hasAutoDns"`
	HasDNSSec          bool         `json:"hasDnsSec"`
	Status             string       `json:"status"`
}
type Nameserver struct {
	Hostname string `json:"hostname"`
	Ipv4     string `json:"ipv4"`
	Ipv6     string `json:"ipv6"`
}
type Contact struct {
	Type        string `json:"type"`
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	CompanyName string `json:"companyName"`
	CompanyKvk  string `json:"companyKvk"`
	CompanyType string `json:"companyType"`
	Street      string `json:"street"`
	Number      string `json:"number"`
	PostalCode  string `json:"postalCode"`
	City        string `json:"city"`
	PhoneNumber string `json:"phoneNumber"`
	FaxNumber   string `json:"faxNumber"`
	Email       string `json:"email"`
	Country     string `json:"country"`
}
