package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeDesec is an in-memory stand-in for the deSEC RRset API. It implements
// just what the solver uses: GET, POST (collection), PATCH and DELETE on
// /api/v1/domains/{zone}/rrsets/{subname}/{type}/, with token authentication.
// It answers the way the real API does for the cases we rely on: 404 for a
// missing RRset or a zone that is not owned, 401 for a wrong token, and 204
// when an RRset is deleted.
type fakeDesec struct {
	t     *testing.T
	token string
	srv   *httptest.Server

	mu     sync.Mutex
	zones  map[string]bool
	rrsets map[string]fakeRRset // key: zone|subname|type
}

type fakeRRset struct {
	Subname string   `json:"subname"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
}

// newFakeDesec starts a fake API that accepts token and owns the given zones.
func newFakeDesec(t *testing.T, token string, zones ...string) *fakeDesec {
	t.Helper()
	f := &fakeDesec{
		t:      t,
		token:  token,
		zones:  make(map[string]bool),
		rrsets: make(map[string]fakeRRset),
	}
	for _, z := range zones {
		f.zones[z] = true
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

// endpoint is the base URL to pass to the solver, including /api/v1.
func (f *fakeDesec) endpoint() string {
	return f.srv.URL + "/api/v1"
}

// seed stores an RRset directly, as if it had been created earlier.
func (f *fakeDesec) seed(zone, subname, rtype string, records ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rrsets[rrsetKey(zone, subname, rtype)] = fakeRRset{
		Subname: subname, Name: fqdnOf(subname, zone), Type: rtype, TTL: 3600, Records: records,
	}
}

// records returns the stored values, and whether the RRset exists.
func (f *fakeDesec) records(zone, subname, rtype string) ([]string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rr, ok := f.rrsets[rrsetKey(zone, subname, rtype)]
	return rr.Records, ok
}

func rrsetKey(zone, subname, rtype string) string {
	return zone + "|" + subname + "|" + rtype
}

func fqdnOf(subname, zone string) string {
	if subname == "" {
		return zone + "."
	}
	return subname + "." + zone + "."
}

func writeDetail(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": detail})
}

func (f *fakeDesec) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if r.Header.Get("Authorization") != "Token "+f.token {
		writeDetail(w, http.StatusUnauthorized, "Invalid token.")
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/domains/")
	if rest == r.URL.Path {
		writeDetail(w, http.StatusNotFound, "Not found.")
		return
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 || parts[1] != "rrsets" {
		writeDetail(w, http.StatusNotFound, "Not found.")
		return
	}
	zone := parts[0]
	if !f.zones[zone] {
		writeDetail(w, http.StatusNotFound, "Not found.")
		return
	}

	switch {
	case len(parts) == 2 && r.Method == http.MethodPost:
		f.create(w, r, zone)
	case len(parts) == 4:
		f.specific(w, r, zone, parts[2], parts[3])
	default:
		writeDetail(w, http.StatusMethodNotAllowed, "Method not allowed.")
	}
}

func (f *fakeDesec) create(w http.ResponseWriter, r *http.Request, zone string) {
	var in fakeRRset
	if err := decodeBody(r, &in); err != nil {
		writeDetail(w, http.StatusBadRequest, err.Error())
		return
	}
	key := rrsetKey(zone, in.Subname, in.Type)
	if _, exists := f.rrsets[key]; exists {
		writeDetail(w, http.StatusBadRequest, "RRset already exists.")
		return
	}
	in.Name = fqdnOf(in.Subname, zone)
	f.rrsets[key] = in
	writeJSON(w, http.StatusCreated, in)
}

func (f *fakeDesec) specific(w http.ResponseWriter, r *http.Request, zone, subname, rtype string) {
	key := rrsetKey(zone, subname, rtype)
	rr, exists := f.rrsets[key]

	switch r.Method {
	case http.MethodGet:
		if !exists {
			writeDetail(w, http.StatusNotFound, "Not found.")
			return
		}
		writeJSON(w, http.StatusOK, rr)

	case http.MethodPatch:
		if !exists {
			writeDetail(w, http.StatusNotFound, "Not found.")
			return
		}
		var in struct {
			TTL     *int      `json:"ttl"`
			Records *[]string `json:"records"`
		}
		if err := decodeBody(r, &in); err != nil {
			writeDetail(w, http.StatusBadRequest, err.Error())
			return
		}
		if in.TTL != nil {
			rr.TTL = *in.TTL
		}
		if in.Records != nil {
			if len(*in.Records) == 0 {
				delete(f.rrsets, key)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			rr.Records = *in.Records
		}
		f.rrsets[key] = rr
		writeJSON(w, http.StatusOK, rr)

	case http.MethodDelete:
		if !exists {
			writeDetail(w, http.StatusNotFound, "Not found.")
			return
		}
		delete(f.rrsets, key)
		w.WriteHeader(http.StatusNoContent)

	default:
		writeDetail(w, http.StatusMethodNotAllowed, "Method not allowed.")
	}
}

func decodeBody(r *http.Request, v interface{}) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("invalid JSON body: %v", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
