# Cluster-level configuration

Manifests here configure the **cluster**, not the IdP. They are shared with everything
else running on it — `networco.no` and `api.networco.no` are served by the same Traefik.

**Nothing in this directory is applied by any workflow.** `deploy-test.yml` and
`release.yml` copy `deploy/k3s/0*.yaml` and apply four named files from it; this
directory is outside that path on purpose. An IdP release must never reconfigure
cluster-wide ingress — a bad value here takes down every site, not just this one.

Apply by hand, one cluster at a time, and watch it.

## Files

| File | Cluster | Notes |
|---|---|---|
| `traefik-test.yaml` | test (`tst01`) | identical values to prod since 2026-08-19 |
| `traefik-prod.yaml` | prod (`srv01/02/03`) | identical values to test since 2026-08-19 |

Since the cert-manager migration (2026-08-19) the two files carry **identical
values**: Traefik holds no certificate state, so nothing env-specific remains.
`networco-app` carries the same values in
`infrastructure/k3s/manifests/00-traefik-config.yaml`, applied by its `deploy.sh` on
every release — **the three files manage the same cluster object; change all of them
together or a later app deploy reverts your change.**

## The design (post-migration)

- **TLS**: every host's certificate is a `kubernetes.io/tls` Secret named
  `<host>-tls`, owned by a cert-manager `Certificate` and referenced by its
  Ingress/IngressRoute. Issuance/renewal is Let's Encrypt **HTTP-01** through the
  `letsencrypt-http01` ClusterIssuer — no DNS credentials involved. The IdP's
  Certificate rides in `deploy/k3s/06-ingress.yaml`; the app hosts' live in
  `networco-app`.
- **Traefik**: a **DaemonSet** (one pod per node) with **no ACME resolver and no
  persistence**, and `service.spec.externalTrafficPolicy: Local`.
- **Client IPs are real**: `Local` skips kube-proxy's SNAT, so Traefik stamps the
  actual client address into `X-Forwarded-For`. Verified on both clusters on
  2026-08-19: prod `audit_logs` recorded a real public address where every prior
  row had the CNI gateway (`10.42.0.1` / `10.42.1.1`).

## Rules that keep it working

- **Do NOT re-add `certificatesresolvers` to any Traefik config.** Besides
  re-introducing RWO cert state (which forces a single replica and breaks
  `Local` on multi-node prod), the resolver intercepts every
  `/.well-known/acme-challenge/` request on port 80 and 404s cert-manager's
  HTTP-01 challenges — the two cannot coexist.
- **Do NOT remove `externalTrafficPolicy: Local`.** With the chart-default
  `Cluster` policy every request arrives as the CNI gateway: per-IP rate limits
  become one global budget and audit trails lose the client address.
- A new HTTPS host needs: a `Certificate` (issuer `letsencrypt-http01`, secret
  `<host>-tls`) plus `secretName` on its Ingress/IngressRoute. Nothing in the
  Traefik config changes.
- k3s installs Traefik from a `HelmChart`, so a `HelmChartConfig` is the only
  durable way to change it. **A `kubectl patch` on the Service is reverted by the
  helm-controller** — it will appear to work and then quietly undo itself.

## Applying

```bash
export KUBECONFIG=~/.kube/networco-tailscale.yaml
kubectl --context networco-test apply -f deploy/cluster/traefik-test.yaml
```

The default context is **prod**, so always pass `--context` explicitly.

## Verifying a file still matches its cluster

```bash
kubectl --context networco-test diff -f deploy/cluster/traefik-test.yaml
```

Empty output means no drift. Run the prod equivalent before touching
`traefik-prod.yaml`.

## History

- Until 2026-08-18 this configuration was cluster-only state; that is how the
  client-IP problem stayed invisible for months.
- Until 2026-08-19 Traefik ran its own ACME resolver against an RWO volume,
  which pinned it to one replica; on 3-node prod that made
  `externalTrafficPolicy: Local` impossible (two nodes would blackhole), so
  every request was SNAT'd and arrived as `10.42.0.1`. The fix: move TLS to
  cert-manager Secrets (bootstrapped by extracting Traefik's existing certs from
  `acme.json`, so no re-issuance was needed for the cutover), then run Traefik
  stateless as a DaemonSet with `Local`.
- The `*.networco.countdown.no` legacy redirect was retired the same day (the
  addresses are no longer in use); its IngressRoute, Middleware and certs were
  deleted from both clusters.
