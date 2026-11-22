[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/cert-manager-webhook-desec)](https://artifacthub.io/packages/helm/cert-manager-webhook-desec/cert-manager-webhook-desec)
[![License](https://img.shields.io/github/license/aellwein/cert-manager-webhook-desec)](https://github.com/aellwein/cert-manager-webhook-desec/blob/main/LICENSE)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/aellwein/cert-manager-webhook-desec)](https://github.com/aellwein/cert-manager-webhook-desec/releases/latest)


cert-manager-webhook-desec
==========================

[cert-manager](https://cert-manager.io) webhook implementation for use
with [deSEC](https://desec.io) provider for solving [ACME DNS-01
challenges](https://cert-manager.io/docs/configuration/acme/dns01/).

Usage
-----

For the deSEC-specific configuration, you will need to create a Kubernetes
secret containing a deSEC API token first. Create the token in the deSEC
web interface, or via the [token API](https://desec.readthedocs.io/en/latest/auth/tokens.html).
A token that can only write the ``_acme-challenge`` RRsets of your zones is
enough for this webhook.

```sh
kubectl create secret generic desec-secret -n cert-manager --from-literal=api-token=<api-token-from-desec>
```

The secret is read on every challenge, so nothing needs restarting if you
change the token.

After creating the secret, configure the ``Issuer``/``ClusterIssuer`` of
yours to have the following configuration (as assumed, secret is
called "desec-secret" and located in namespace "cert-manager"):

```yml
apiVersion: cert-manager.io/v1
kind: Issuer   # may also be a ClusterIssuer
...
spec:
    solvers:
    - dns01:
        webhook:
            groupName: com.desec.webhook
            solverName: desec
            config:
                secretRef: desec-secret
                secretNamespace: cert-manager
```
For more details, please refer to https://cert-manager.io/docs/configuration/acme/dns01/#configuring-dns01-challenge-provider

Now, the actual webhook can be installed via Helm chart:
```
helm install webhook-desec oci://ghcr.io/aellwein/cert-manager-webhook-desec/cert-manager-webhook-desec --namespace cert-manager
```
From that point, the issuer configured above should be able to solve
the DNS01 challenges using ``cert-manager-webhook-desec``.


Testing
-------

Unit tests run against an in-memory fake of the deSEC API and need no
credentials:

```sh
go test ./...
```

Integration tests run against the live deSEC API. They create and remove
TXT records under ``_acme-challenge.cert-manager-itest.<domain>`` and are
skipped unless both variables are set:

```sh
DESEC_API_TOKEN=... DESEC_TEST_DOMAIN=example.com go test -run Integration -v
```


Disclaimer
----------

I am in no way affiliated or associated with deSEC and this project
is done in my spare time.


License
-------

Apache 2.0, see [LICENSE](./LICENSE).
