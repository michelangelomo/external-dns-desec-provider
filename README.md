# deSEC webhook for ExternalDNS

> [!WARNING]  
> This webhook is still under development. Use at your own risk.

`external-dns-desec-provider` extends the functionality of [ExternalDNS](https://github.com/kubernetes-sigs/external-dns), a Kubernetes external component for managing DNS records.

## Usage

A deSEC API token is required for this webhook to function properly. Please read the official documentation for creating tokens: https://desec.readthedocs.io/en/latest/auth/tokens.html

## Deployment

In this example we're using the [ExternalDNS official chart](https://kubernetes-sigs.github.io/external-dns/latest/charts/external-dns/).

First of all, you need to save you deSEC token somewhere, for example:

```yaml
kubectl create secret generic desec-credentials --from-literal=api-token='<YOUR_DESEC_API_TOKEN>' -n external-dns
```

Then add the official Helm repo and update:

```shell
helm repo add external-dns https://kubernetes-sigs.github.io/external-dns/ && helm repo update
```

After that, create a custom value files, for example `values.yaml`:

```yaml
namespace: external-dns
provider:
  name: webhook
  webhook:
    image:
      repository: ghcr.io/michelangelomo/external-dns-desec-provider
      tag: latest
    env:
      - name: WEBHOOK_APITOKEN
        valueFrom:
          secretKeyRef:
            name: desec-credentials
            key: api-token
      - name: WEBHOOK_DOMAINFILTERS
        value: "example.com,example.org"
    livenessProbe:
      httpGet:
        path: /healthz
        port: http-webhook
      initialDelaySeconds: 10
      timeoutSeconds: 5
    readinessProbe:
      httpGet:
        path: /readyz
        port: http-webhook
      initialDelaySeconds: 10
      timeoutSeconds: 5
```

Then install ExternalDNS:

```shell
# install external-dns with helm
helm install external-dns external-dns/external-dns -f values.yaml -n external-dns
```

This value file will run webhook server along with external-dns as sidecar.

## Environment Variables

### deSEC API Configuration

| Variable                | Description                        | Notes             |
| ----------------------- | ---------------------------------- | ----------------- |
| WEBHOOK_APITOKEN       | deSEC API token                    | Mandatory         |
| WEBHOOK_DRYRUN         | If set, changes won't be applied   | Default: `false`  |
| WEBHOOK_DOMAINFILTERS  | List of domains to manage, comma separated          | Mandatory         |
| WEBHOOK_DEFAULTTTL     | Default TTL if not specified       | Default: `3600`  |

> [!NOTE]   
> deSEC requires a minimum TTL of 3600 seconds (https://desec.readthedocs.io/en/latest/dns/domains.html#domain-object)

### Server Configuration

| Variable              | Description                    | Notes                |
| --------------------- | ------------------------------ | -------------------- |
| WEBHOOK_ADDRESS       | Webhook hostname or IP address | Default: `127.0.0.1` |
| WEBHOOK_PORT          | Webhook port                   | Default: `8888`      |
| WEBHOOK_LOGLEVEL     | Log level (debug, info, etc.)  | Default: `info`      |

### Healthcheck configuration

| Variable              | Description                    | Notes                |
| --------------------- | ------------------------------ | -------------------- |
| WEBHOOK_HEALTHADDRESS       | Healthcheck hostname or IP address | Default: `0.0.0.0` |
| WEBHOOK_HEALTHPORT          | Webhook port                   | Default: `8080`      |

## Local Development

```shell
# Run locally
export WEBHOOK_API_TOKEN=your_api_key
export WEBHOOK_DOMAINFILTERS=example.com,example.org
go run cmd/webhook.go

# OR build the Docker image locally
docker build -t external-dns-desec-provider .
```