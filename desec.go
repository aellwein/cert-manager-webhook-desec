package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultDesecEndpoint is the base URL of the deSEC DNS API.
const defaultDesecEndpoint = "https://desec.io/api/v1"

// desecTXTTTL is the TTL for challenge records. deSEC rejects TTLs below the
// zone's minimum_ttl, so 3600 is a safe value for every zone.
const desecTXTTTL = 3600

// desecClient is a minimal client for the deSEC RRset endpoints. It uses only
// net/http from the standard library.
type desecClient struct {
	endpoint string
	token    string
	http     *http.Client
}

// desecRRset is the RRset object as described in the deSEC API docs.
type desecRRset struct {
	Subname string   `json:"subname"`
	Name    string   `json:"name,omitempty"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
}

func newDesecClient(endpoint, token string) *desecClient {
	if endpoint == "" {
		endpoint = defaultDesecEndpoint
	}
	return &desecClient{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		token:    token,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
}

// rrsetURL returns the endpoint of one RRset. The zone apex is addressed by
// "@", as the deSEC docs describe.
func (c *desecClient) rrsetURL(zone, subname, rtype string) string {
	if subname == "" {
		subname = "@"
	}
	return fmt.Sprintf("%s/domains/%s/rrsets/%s/%s/",
		c.endpoint, url.PathEscape(zone), url.PathEscape(subname), url.PathEscape(rtype))
}

// getRRset returns the RRset, and false if it does not exist.
func (c *desecClient) getRRset(zone, subname, rtype string) (*desecRRset, bool, error) {
	status, body, err := c.do(http.MethodGet, c.rrsetURL(zone, subname, rtype), nil)
	if err != nil {
		return nil, false, err
	}
	switch status {
	case http.StatusOK:
		var rr desecRRset
		if err := json.Unmarshal(body, &rr); err != nil {
			return nil, false, fmt.Errorf("decoding RRset: %v", err)
		}
		return &rr, true, nil
	case http.StatusNotFound:
		return nil, false, nil
	default:
		return nil, false, apiError(http.MethodGet, status, body)
	}
}

// createRRset creates a new RRset in the zone.
func (c *desecClient) createRRset(zone string, rr desecRRset) error {
	endpoint := fmt.Sprintf("%s/domains/%s/rrsets/", c.endpoint, url.PathEscape(zone))
	status, body, err := c.do(http.MethodPost, endpoint, rr)
	if err != nil {
		return err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return apiError(http.MethodPost, status, body)
	}
	return nil
}

// setRecords replaces the record values of an existing RRset. The API expects
// the complete list, so callers must read the RRset first.
func (c *desecClient) setRecords(zone, subname, rtype string, records []string) error {
	body := map[string][]string{"records": records}
	status, respBody, err := c.do(http.MethodPatch, c.rrsetURL(zone, subname, rtype), body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError(http.MethodPatch, status, respBody)
	}
	return nil
}

// deleteRRset removes an RRset. A missing RRset is not an error.
func (c *desecClient) deleteRRset(zone, subname, rtype string) error {
	status, body, err := c.do(http.MethodDelete, c.rrsetURL(zone, subname, rtype), nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusNotFound {
		return apiError(http.MethodDelete, status, body)
	}
	return nil
}

// do sends one authenticated request. A non-nil payload is sent as JSON.
func (c *desecClient) do(method, endpoint string, payload interface{}) (int, []byte, error) {
	var reader io.Reader
	if payload != nil {
		buf, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, fmt.Errorf("encoding request: %v", err)
		}
		reader = strings.NewReader(string(buf))
	}

	req, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Token "+c.token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %v", method, endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("reading response: %v", err)
	}
	return resp.StatusCode, body, nil
}

// apiError turns a failed response into an error that carries the API's
// own "detail" message when it has one.
func apiError(method string, status int, body []byte) error {
	var parsed struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &parsed) == nil && parsed.Detail != "" {
		return fmt.Errorf("deSEC API %s returned HTTP %d: %s", method, status, parsed.Detail)
	}
	return fmt.Errorf("deSEC API %s returned HTTP %d", method, status)
}

// desecSubname returns the subname of fqdn relative to zone, for example
// "_acme-challenge.www" for "_acme-challenge.www.example.com." in
// "example.com.". Both names may carry a trailing dot or not.
func desecSubname(fqdn, zone string) (string, error) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")
	if fqdn == zone {
		return "", fmt.Errorf("%s is the zone apex, not a challenge name", fqdn)
	}
	if !strings.HasSuffix(fqdn, "."+zone) {
		return "", fmt.Errorf("%s is not inside zone %s", fqdn, zone)
	}
	return strings.TrimSuffix(fqdn, "."+zone), nil
}

// txtValue quotes a challenge key as a TXT record value, as deSEC requires.
func txtValue(key string) string {
	return `"` + key + `"`
}
