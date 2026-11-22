package main

import (
	"strings"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// These tests drive the solver through Present and CleanUp, as cert-manager
// does, against the in-memory fake from desec_fake_test.go. They need no
// network and no credentials, so they run in every `go test`.

const (
	fakeSecretName = "desec-fake-secret"
	fakeToken      = "fake-desec-token-for-offline-tests"
	fakeZone       = "example.com"
)

// newTestSolver returns a solver whose cluster holds a secret with the given
// token and whose API calls go to the fake.
func newTestSolver(t *testing.T, f *fakeDesec, token string) *desecDNSProviderSolver {
	t.Helper()
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: fakeSecretName, Namespace: "default"},
		Data:       map[string][]byte{"api-token": []byte(token)},
	}
	return &desecDNSProviderSolver{
		client:      fake.NewClientset(sec),
		apiEndpoint: f.endpoint(),
	}
}

// challengeFor builds the request cert-manager sends for a dns-01 challenge.
// resolvedFqdn must lie in zone.
func challengeFor(resolvedFqdn, zone, key string) *v1alpha1.ChallengeRequest {
	return &v1alpha1.ChallengeRequest{
		Action:            v1alpha1.ChallengeActionPresent,
		Type:              "dns-01",
		DNSName:           zone,
		Key:               key,
		ResourceNamespace: "default",
		ResolvedFQDN:      resolvedFqdn + ".",
		ResolvedZone:      zone + ".",
		Config:            &extapi.JSON{Raw: []byte(`{"secretRef":"` + fakeSecretName + `"}`)},
	}
}

const challengeName = "_acme-challenge." + fakeZone

func TestPresentCreatesTXTRRset(t *testing.T) {
	f := newFakeDesec(t, fakeToken, fakeZone)
	s := newTestSolver(t, f, fakeToken)

	if err := s.Present(challengeFor(challengeName, fakeZone, "key-one")); err != nil {
		t.Fatalf("Present: %v", err)
	}

	got, ok := f.records(fakeZone, "_acme-challenge", "TXT")
	if !ok {
		t.Fatal("expected a TXT RRset at _acme-challenge, found none")
	}
	if len(got) != 1 || got[0] != `"key-one"` {
		t.Fatalf("records = %q, want [\"\\\"key-one\\\"\"]", got)
	}
}

// cert-manager presents one value per name it validates. A wildcard plus the
// base domain produces two challenges on the same name, so both must survive.
func TestPresentAddsSecondValueAndKeepsFirst(t *testing.T) {
	f := newFakeDesec(t, fakeToken, fakeZone)
	s := newTestSolver(t, f, fakeToken)

	for _, key := range []string{"key-one", "key-two"} {
		if err := s.Present(challengeFor(challengeName, fakeZone, key)); err != nil {
			t.Fatalf("Present(%s): %v", key, err)
		}
	}

	got, _ := f.records(fakeZone, "_acme-challenge", "TXT")
	if len(got) != 2 || !containsString(got, `"key-one"`) || !containsString(got, `"key-two"`) {
		t.Fatalf("records = %q, want both key-one and key-two", got)
	}
}

func TestPresentSameValueTwiceIsIdempotent(t *testing.T) {
	f := newFakeDesec(t, fakeToken, fakeZone)
	s := newTestSolver(t, f, fakeToken)

	for i := 0; i < 2; i++ {
		if err := s.Present(challengeFor(challengeName, fakeZone, "key-one")); err != nil {
			t.Fatalf("Present attempt %d: %v", i+1, err)
		}
	}

	got, _ := f.records(fakeZone, "_acme-challenge", "TXT")
	if len(got) != 1 {
		t.Fatalf("records = %q, want exactly one value", got)
	}
}

// For a name below a subdomain, the record must land in the zone's RRset with
// the full relative name as subname.
func TestPresentUsesRelativeSubnameBelowSubdomain(t *testing.T) {
	f := newFakeDesec(t, fakeToken, fakeZone)
	s := newTestSolver(t, f, fakeToken)

	name := "_acme-challenge.www." + fakeZone
	if err := s.Present(challengeFor(name, fakeZone, "key-one")); err != nil {
		t.Fatalf("Present: %v", err)
	}

	if _, ok := f.records(fakeZone, "_acme-challenge.www", "TXT"); !ok {
		t.Fatal("expected a TXT RRset at _acme-challenge.www in the zone")
	}
}

func TestCleanUpRemovesOnlyOwnValue(t *testing.T) {
	f := newFakeDesec(t, fakeToken, fakeZone)
	f.seed(fakeZone, "_acme-challenge", "TXT", `"other"`, `"key-one"`)
	s := newTestSolver(t, f, fakeToken)

	if err := s.CleanUp(challengeFor(challengeName, fakeZone, "key-one")); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}

	got, ok := f.records(fakeZone, "_acme-challenge", "TXT")
	if !ok || len(got) != 1 || got[0] != `"other"` {
		t.Fatalf("records = %q (exists=%v), want only the foreign value", got, ok)
	}
}

func TestCleanUpDeletesRRsetWhenLastValueGoes(t *testing.T) {
	f := newFakeDesec(t, fakeToken, fakeZone)
	f.seed(fakeZone, "_acme-challenge", "TXT", `"key-one"`)
	s := newTestSolver(t, f, fakeToken)

	if err := s.CleanUp(challengeFor(challengeName, fakeZone, "key-one")); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}

	if _, ok := f.records(fakeZone, "_acme-challenge", "TXT"); ok {
		t.Fatal("expected the RRset to be deleted after its last value was removed")
	}
}

// cert-manager may call CleanUp again when a challenge is retried, so a
// missing RRset must not be an error.
func TestCleanUpMissingRRsetIsNoop(t *testing.T) {
	f := newFakeDesec(t, fakeToken, fakeZone)
	s := newTestSolver(t, f, fakeToken)

	if err := s.CleanUp(challengeFor(challengeName, fakeZone, "key-one")); err != nil {
		t.Fatalf("CleanUp on missing RRset: %v", err)
	}
}

func TestCleanUpValueNotPresentIsNoop(t *testing.T) {
	f := newFakeDesec(t, fakeToken, fakeZone)
	f.seed(fakeZone, "_acme-challenge", "TXT", `"other"`)
	s := newTestSolver(t, f, fakeToken)

	if err := s.CleanUp(challengeFor(challengeName, fakeZone, "key-one")); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}

	got, ok := f.records(fakeZone, "_acme-challenge", "TXT")
	if !ok || len(got) != 1 || got[0] != `"other"` {
		t.Fatalf("records = %q (exists=%v), want the foreign value untouched", got, ok)
	}
}

func TestPresentFailsForZoneNotOwned(t *testing.T) {
	f := newFakeDesec(t, fakeToken) // owns no zones
	s := newTestSolver(t, f, fakeToken)

	err := s.Present(challengeFor(challengeName, fakeZone, "key-one"))
	if err == nil {
		t.Fatal("Present succeeded for a zone that is not owned")
	}
}

func TestPresentFailsWithWrongToken(t *testing.T) {
	f := newFakeDesec(t, fakeToken, fakeZone)
	s := newTestSolver(t, f, "wrong-token")

	err := s.Present(challengeFor(challengeName, fakeZone, "key-one"))
	if err == nil {
		t.Fatal("Present succeeded with a wrong token")
	}
	if !strings.Contains(err.Error(), "Invalid token") {
		t.Fatalf("error %q does not carry the API's message", err)
	}
}

func TestPresentFailsWithoutSecret(t *testing.T) {
	f := newFakeDesec(t, fakeToken, fakeZone)
	s := &desecDNSProviderSolver{client: fake.NewClientset(), apiEndpoint: f.endpoint()}

	if err := s.Present(challengeFor(challengeName, fakeZone, "key-one")); err == nil {
		t.Fatal("Present succeeded without the referenced secret")
	}
}

func TestPresentFailsWithoutApiTokenKey(t *testing.T) {
	f := newFakeDesec(t, fakeToken, fakeZone)
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: fakeSecretName, Namespace: "default"},
		Data:       map[string][]byte{"api-key": []byte(fakeToken)},
	}
	s := &desecDNSProviderSolver{client: fake.NewClientset(sec), apiEndpoint: f.endpoint()}

	err := s.Present(challengeFor(challengeName, fakeZone, "key-one"))
	if err == nil || !strings.Contains(err.Error(), "api-token") {
		t.Fatalf("error = %v, want one naming the missing api-token key", err)
	}
}

func TestPresentAndCleanUpLifecycle(t *testing.T) {
	f := newFakeDesec(t, fakeToken, fakeZone)
	s := newTestSolver(t, f, fakeToken)
	ch := challengeFor(challengeName, fakeZone, "key-one")

	if err := s.Present(ch); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := s.Present(ch); err != nil {
		t.Fatalf("Present retry: %v", err)
	}
	if err := s.CleanUp(ch); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if err := s.CleanUp(ch); err != nil {
		t.Fatalf("CleanUp retry: %v", err)
	}
	if _, ok := f.records(fakeZone, "_acme-challenge", "TXT"); ok {
		t.Fatal("RRset still present after CleanUp")
	}
}

func TestDesecSubnameFromChallenge(t *testing.T) {
	tests := []struct {
		name    string
		fqdn    string
		zone    string
		want    string
		wantErr bool
	}{
		{"apex-level challenge", "_acme-challenge.example.com.", "example.com.", "_acme-challenge", false},
		{"subdomain challenge", "_acme-challenge.www.example.com.", "example.com.", "_acme-challenge.www", false},
		{"no trailing dot", "_acme-challenge.example.com", "example.com", "_acme-challenge", false},
		{"fqdn outside zone", "_acme-challenge.other.org.", "example.com.", "", true},
		{"fqdn is the zone apex", "example.com.", "example.com.", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := desecSubname(tt.fqdn, tt.zone)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("subname = %q, want %q", got, tt.want)
			}
		})
	}
}
