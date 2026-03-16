# Local Development Services

After running `make up` or `make dev svc=<name> observability=true`:

| UI | URL | Purpose | Started by |
|---|---|---|---|
| Jaeger | http://localhost:16686 | Distributed tracing | `make up` or `make dev ... observability=true` or `make jaeger` |
| Kafka UI | http://localhost:8080 | Topic browser, consumer groups, message inspector | `make up` or `make up-infra` |
| pgAdmin | http://localhost:5050 | Postgres query tool and schema browser | `make up` or `make dev svc=<any-postgres-service>` |
| Prometheus metrics | http://localhost:{METRICS_PORT}/metrics | Raw metrics exposition (not a UI) | Emitted by each running service |

## pgAdmin first-time setup
Login: `admin@cybersiren.dev` / `admin` (local dev only)
Add server: Host=`postgres`, Port=`5432`, DB/User/Pass from your `.env`

## Jaeger tips
- Traces only appear if `JAEGER_ENDPOINT` is set in `.env`
- Set `JAEGER_ENDPOINT=http://localhost:4318` in `.env` when running with `observability=true`
- Select service name in the dropdown — each service registers under its own name

## Kafka UI tips
- Topics appear after `make db-setup` runs `kafka-init`
- Consumer groups appear once pipeline services are running
- Use the message browser to inspect payloads per topic and partition
