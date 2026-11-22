package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var (
	GroupName        = os.Getenv("GROUP_NAME")
	version   string = "0.0.0-dev"
)

func main() {
	klog.Infof("starting cert-manager-webhook-desec (version %s)", version)
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}
	cmd.RunWebhookServer(GroupName,
		&desecDNSProviderSolver{},
	)
}

// desecClientConfig holds the credentials for the deSEC API, read from the
// Kubernetes secret referenced by the Issuer.
type desecClientConfig struct {
	// apiToken is the deSEC API token. Create a token scoped to the
	// _acme-challenge RRsets of the zones it should manage.
	apiToken string
}

// desecDNSProviderSolver implements the cert-manager webhook solver interface.
type desecDNSProviderSolver struct {
	// client reads the secret. It is the interface so tests can use a fake.
	client kubernetes.Interface
	// apiEndpoint overrides the deSEC API base URL. Only set in tests.
	apiEndpoint string
}

// desecDNSProviderConfig is the solver config in the Issuer/ClusterIssuer.
type desecDNSProviderConfig struct {
	// name of the secret which contains the deSEC API token
	SecretRef string `json:"secretRef"`
	// optional namespace for the secret
	SecretNamespace string `json:"secretNamespace"`
}

func (s *desecDNSProviderSolver) Name() string {
	return "desec"
}

// Present creates the _acme-challenge TXT record for the challenge. If the
// RRset already holds other challenge values, the new one is added to them.
func (s *desecDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := s.getConfig(ch)
	if err != nil {
		return err
	}
	zone, subname, err := challengeTarget(ch)
	if err != nil {
		return err
	}

	client := newDesecClient(s.apiEndpoint, cfg.apiToken)
	value := txtValue(ch.Key)

	rr, found, err := client.getRRset(zone, subname, "TXT")
	if err != nil {
		return fmt.Errorf("reading TXT RRset %s in %s: %v", subname, zone, err)
	}
	if !found {
		err := client.createRRset(zone, desecRRset{
			Subname: subname,
			Type:    "TXT",
			TTL:     desecTXTTTL,
			Records: []string{value},
		})
		if err != nil {
			return fmt.Errorf("creating TXT RRset %s in %s: %v", subname, zone, err)
		}
	} else {
		if containsString(rr.Records, value) {
			return nil
		}
		records := append(append([]string{}, rr.Records...), value)
		if err := client.setRecords(zone, subname, "TXT", records); err != nil {
			return fmt.Errorf("adding value to TXT RRset %s in %s: %v", subname, zone, err)
		}
	}

	klog.Infof("presented challenge for '%s' via the deSEC API", ch.ResolvedFQDN)
	return nil
}

// CleanUp removes this challenge's value from the TXT RRset. The RRset is
// deleted once no values are left. Other values, such as those of a second
// challenge on the same name, are kept.
func (s *desecDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := s.getConfig(ch)
	if err != nil {
		return err
	}
	zone, subname, err := challengeTarget(ch)
	if err != nil {
		return err
	}

	client := newDesecClient(s.apiEndpoint, cfg.apiToken)
	value := txtValue(ch.Key)

	rr, found, err := client.getRRset(zone, subname, "TXT")
	if err != nil {
		return fmt.Errorf("reading TXT RRset %s in %s: %v", subname, zone, err)
	}
	if !found || !containsString(rr.Records, value) {
		return nil
	}

	remaining := make([]string, 0, len(rr.Records)-1)
	for _, r := range rr.Records {
		if r != value {
			remaining = append(remaining, r)
		}
	}
	if len(remaining) == 0 {
		if err := client.deleteRRset(zone, subname, "TXT"); err != nil {
			return fmt.Errorf("deleting TXT RRset %s in %s: %v", subname, zone, err)
		}
	} else if err := client.setRecords(zone, subname, "TXT", remaining); err != nil {
		return fmt.Errorf("removing value from TXT RRset %s in %s: %v", subname, zone, err)
	}

	klog.Infof("cleaned up challenge for '%s' via the deSEC API", ch.ResolvedFQDN)
	return nil
}

// Initialize is called once by the webhook server with the in-cluster config.
func (s *desecDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	s.client = cl
	return nil
}

// challengeTarget returns the zone and the RRset subname for a challenge.
func challengeTarget(ch *v1alpha1.ChallengeRequest) (string, string, error) {
	zone := strings.TrimSuffix(ch.ResolvedZone, ".")
	subname, err := desecSubname(ch.ResolvedFQDN, zone)
	if err != nil {
		return "", "", err
	}
	return zone, subname, nil
}

func (s *desecDNSProviderSolver) getConfig(ch *v1alpha1.ChallengeRequest) (*desecClientConfig, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	secretNs := ch.ResourceNamespace
	if cfg.SecretNamespace != "" {
		secretNs = cfg.SecretNamespace
	}

	sec, err := s.client.CoreV1().Secrets(secretNs).Get(context.TODO(), cfg.SecretRef, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get secret '%s/%s': %v", secretNs, cfg.SecretRef, err)
	}

	token, ok := sec.Data["api-token"]
	if !ok || len(token) == 0 {
		return nil, fmt.Errorf("secret '%s/%s' has no 'api-token' key", secretNs, cfg.SecretRef)
	}
	return &desecClientConfig{apiToken: string(token)}, nil
}

func loadConfig(cfgJSON *extapi.JSON) (desecDNSProviderConfig, error) {
	cfg := desecDNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}
	return cfg, nil
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
