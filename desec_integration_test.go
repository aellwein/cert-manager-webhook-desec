package main

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// Integration tests run against the live deSEC API and are skipped unless
// both DESEC_API_TOKEN and DESEC_TEST_DOMAIN are set:
//
//	DESEC_API_TOKEN=... DESEC_TEST_DOMAIN=example.com go test -run Integration -v
//
// They create and remove TXT records under
// _acme-challenge.cert-manager-itest.<domain> and touch nothing else.
const integrationHost = "cert-manager-itest"

// integrationTarget returns a solver wired to the real API, and the FQDN to
// test against. It skips the test when the environment is not configured.
func integrationTarget(t *testing.T) (*desecDNSProviderSolver, string, string) {
	t.Helper()
	token := os.Getenv("DESEC_API_TOKEN")
	domain := strings.TrimSuffix(os.Getenv("DESEC_TEST_DOMAIN"), ".")
	if token == "" || domain == "" {
		t.Skip("set DESEC_API_TOKEN and DESEC_TEST_DOMAIN to run integration tests")
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: fakeSecretName, Namespace: "default"},
		Data:       map[string][]byte{"api-token": []byte(token)},
	}
	s := &desecDNSProviderSolver{client: fake.NewClientset(sec)} // default endpoint
	return s, "_acme-challenge." + integrationHost + "." + domain, domain
}

// challengeKey returns a value shaped like the one cert-manager presents:
// base64url of a SHA-256 digest, which is 43 characters.
func challengeKey(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// The sequence cert-manager drives: present, present again on retry, clean up,
// and clean up again when the challenge is retried after validation.
func TestIntegrationChallengeLifecycle(t *testing.T) {
	s, fqdn, zone := integrationTarget(t)
	key := challengeKey(t)
	ch := challengeFor(fqdn, zone, key)

	// Make sure nothing from an aborted earlier run is left behind.
	t.Cleanup(func() {
		if err := s.CleanUp(ch); err != nil {
			t.Errorf("cleanup of test record failed: %v", err)
		}
	})

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
}
