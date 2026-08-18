# Cluster-level configuration

Manifests here configure the **cluster**, not the IdP. They are shared with everything
else running on it — `networco.no` and `api.networco.no` are served by the same Traefik.

**Nothing in this directory is applied by any workflow.** `deploy-test.yml` and
`release.yml` copy `deploy/k3s/0*.yaml` and apply four named files from it; this
directory is outside that path on purpose. An IdP release must never reconfigure
cluster-wide ingress — a bad value here takes down every site, not just this one.

Apply by hand, one cluster at a time, and watch it.

## Why these live in git

They were cluster-only state until 2026-08-18. That is how the client-IP problem below
stayed invisible: nothing in any repo described the setting that caused it, so there was
no diff to read and no history to blame. A cluster rebuild would also have silently
reverted it.

## Files

| File | Cluster | Notes |
|---|---|---|
| `traefik-test.yaml` | test (`tst01`) | single node; `externalTrafficPolicy: Local` |
| `traefik-prod.yaml` | prod (`srv01/02/03`) | three nodes; policy left at the `Cluster` default — see below |

They differ in exactly two things: `persistence.storageClass` (`local-path` vs
`longhorn`) and the `service.spec` block that only test has.

## Applying

k3s installs Traefik from a `HelmChart`, so a `HelmChartConfig` is the only durable way
to change it. **A `kubectl patch` on the Service is reverted by the helm-controller** —
it will appear to work and then quietly undo itself.

```bash
export KUBECONFIG=~/.kube/networco-tailscale.yaml
kubectl --context networco-test apply -f deploy/cluster/traefik-test.yaml
```

The default context is **prod**, so always pass `--context` explicitly.

Applying restarts Traefik. The chart uses `updateStrategy: Recreate` (the old pod is
terminated before the new one starts, because the ACME volume is RWO and a rolling
update deadlocks on it), so expect a brief ingress blip on every change.

## Verifying a file still matches its cluster

Both files are byte-identical to what is live. Check before editing, so you never apply a
file that has drifted from reality:

```bash
kubectl --context networco-test diff -f deploy/cluster/traefik-test.yaml
```

Empty output means no drift. Run the prod equivalent before touching `traefik-prod.yaml`.

## The client-IP problem, and why prod does not have the fix

With the chart default (`externalTrafficPolicy: Cluster`) kube-proxy SNATs the connection
before Traefik sees it, so Traefik stamps `X-Forwarded-For` with the CNI gateway
`10.42.0.1` and **every user collapses into a single address** downstream. The app side is
correct — `Program.cs` configures `ForwardedHeaders.XForwardedFor` with cleared
allowlists and `UseForwardedHeaders()` runs first — it just faithfully records a useless
value.

Consequences in the IdP:

- the per-IP account lockout (10 failures / 30 min) becomes a **global** lockout: ten
  failed logins from anyone locks out everyone
- the per-IP rate limiters become global budgets — including the `auth-strict` cap of
  **5 requests/minute on `POST /oauth/token`**, i.e. five logins per minute for the
  entire user base

Test was fixed on 2026-08-18 with `externalTrafficPolicy: Local`, which skips the SNAT
and delivers straight to a node-local Traefik pod. Confirmed by a real request recording
`81.166.239.243` where all 206 prior audit rows had recorded `10.42.0.1`.

**Prod cannot take that change as it stands.** All three node IPs are round-robined in
DNS, but Traefik runs as a single replica, because its ACME store is one RWO Longhorn
volume. `Local` only delivers to a node-local Traefik pod, so the two nodes without one
would blackhole roughly two thirds of all traffic.

### Sequence to fix prod

The blocker is TLS state, not the policy. Traefik has to be runnable on every node first:

1. Issue certificates through cert-manager for `id.networco.no`, `networco.no` and
   `api.networco.no`. cert-manager is installed with a working `letsencrypt-prod`
   ClusterIssuer but currently issues **nothing** — there are no `Certificate` resources.
   (`wildcard-tls` in the `networco` namespace is for the retired
   `*.networco.countdown.no` and expired on 2026-07-05; it is not usable here.)
2. Switch each ingress from `traefik.ingress.kubernetes.io/router.tls.certresolver` to the
   issued secret, and verify HTTPS on all three hosts. Ingresses live in two repos —
   `networco-id` owns `06-ingress.yaml`, `networco-app` owns the other two.
3. Only once no host depends on the resolver: drop the ACME `additionalArguments` and
   `persistence` from `traefik-prod.yaml`, so Traefik holds no state.
4. Scale Traefik across the nodes (DaemonSet, or replicas with anti-affinity) so every
   node that DNS points at has a local pod.
5. Add the `service.spec.externalTrafficPolicy: Local` block, and confirm real client IPs
   land in `audit_logs.ip_address`.

Sequenced wrong, every prod site loses HTTPS at once. Steps 1–2 are reversible and can be
done well ahead of the rest.
