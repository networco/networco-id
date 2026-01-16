# NetworcoID

Open source Identity Provider for the Networco ecosystem.

## Structure

- `src/NetworcoId.Core`: Shared models, security, and messaging logic.
- `src/NetworcoId.Api`: OAuth2/OIDC compatible identity service.
- `src/NetworcoId.Worker`: Background worker for emails and OTPs.
- `deploy/k3s`: Kubernetes manifests for standalone deployment.

## Deployment

1. Create the namespace: `kubectl apply -f deploy/k3s/00-namespace.yaml`
2. Configure secrets in `deploy/k3s/03-secrets.yaml` and apply.
3. Deploy NATS: `kubectl apply -f deploy/k3s/01-nats.yaml`
4. Deploy API & Worker: `kubectl apply -f deploy/k3s/04-api.yaml -f deploy/k3s/05-worker.yaml`
5. Configure Ingress: `kubectl apply -f deploy/k3s/06-ingress.yaml`

## Development

Run locally using `dotnet run --project src/NetworcoId.Api`.
Ensure NATS is running at `localhost:4222`.
