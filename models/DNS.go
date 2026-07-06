package models

type DNSResponse struct {
	DNSEntries []DNS `json:"dnsEntries"`
}

type DNS struct {
	Name    string `json:"name"`
	Expire  int    `json:"expire"`
	Type    string `json:"type"`
	Content string `json:"content"`
}
