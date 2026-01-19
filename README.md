# NetworcoID

Open source Identity Provider for the Networco ecosystem.

## Structure

- `src/NetworcoId.Core`: Shared models, security, and messaging logic.
- `src/NetworcoId`: OAuth2/OIDC compatible identity service.
- `src/NetworcoId.Worker`: Background worker for emails and OTPs.
- `deploy/k3s`: Kubernetes manifests for standalone deployment.

## Deployment

1. Create the namespace: `kubectl apply -f deploy/k3s/00-namespace.yaml`
2. Configure secrets in `deploy/k3s/03-secrets.yaml` and apply.
3. Deploy NATS: `kubectl apply -f deploy/k3s/01-nats.yaml`
4. Deploy API & Worker: `kubectl apply -f deploy/k3s/04-api.yaml -f deploy/k3s/05-worker.yaml`
5. Configure Ingress: `kubectl apply -f deploy/k3s/06-ingress.yaml`

## Integration

NetworcoID is a standards-compliant OpenID Connect (OIDC) provider.

### OIDC Configuration

The OIDC discovery endpoint is available at:
`https://id.networco.no/.well-known/openid-configuration`

### Client Configuration Example (ASP.NET Core)

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://id.networco.no";
        options.Audience = "your-api-audience";
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://id.networco.no",
            // ... other validation params
        };
    });
```

### Claims Provided

- `sub`: Unique user identifier (GUID)
- `national_id`: User's national ID number
- `email`: User's email address
- `given_name`: First name
- `family_name`: Last name
- `phone_number`: Contact number

## Background Processing

The service uses NATS JetStream for background tasks like sending verification emails and OTP codes. Ensure the `networco-id` stream is provisioned in NATS.

OpenCode shared session: https://opncd.ai/share/r1vjvrP0
