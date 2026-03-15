# httputil

Shared HTTP primitives for CyberSiren microservices.

- **Inbound (server)**: thin abstraction over Gin for routing, middleware, strict JSON parsing, validation, and consistent JSON envelopes.
- **Outbound (client)**: thin abstraction over Resty v3 (beta) for external API calls (WHOIS, VT, URLScan, etc.) with retries/timeouts and normalized errors.

## Package layout

- `server.go`: inbound request parsing/validation and response envelope writers.
- `client.go`: outbound HTTP client configuration, request options, and execution helpers.
- Request/response helpers are intentionally consolidated into these two files (there is no separate `request.go` or `response.go` in this package).

## Inbound usage (`server.go`)

```go
srv := httputil.NewServer()

srv.POST("/v1/scan", func(c httputil.Context) {
	var req CreateScanRequest
	if err := c.ParseAndValidateJSON(&req); err != nil {
		_ = c.RequestError(err)
		return
	}

	resp := map[string]any{"scan_id": 123}
	_ = c.Created(resp)
})

if err := srv.Start(":8080"); err != nil {
	panic(err)
}
```

### Response envelopes

Success:

```json
{
  "success": true,
  "message": "...",
  "data": {}
}
```

Error:

```json
{
  "success": false,
  "error": {
    "status": 400,
    "code": "bad_request",
    "message": "...",
    "details": {}
  }
}
```

## Outbound usage (`client.go`)

```go
type WhoisResponse struct {
	Domain string `json:"domain"`
}

client := httputil.NewClient(
	httputil.WithClientBaseURL("https://whois.example/api"),
	httputil.WithClientTimeout(10*time.Second),
)

var out WhoisResponse
_, err := client.GetJSON(ctx, "/lookup",
	&out,
	httputil.WithClientRequestQueryParam("domain", "example.com"),
	httputil.WithClientRequestExpectedStatus(http.StatusOK),
)
if err != nil {
	// err may be *httputil.ClientError
}
```

## Key helpers

- Inbound parsing/validation: `ParseJSON`, `ParseJSONWithLimit`, `ParseAndValidateJSON`
- Inbound responses: `WriteOK`, `WriteCreated`, `WriteError`, `WriteRequestError`
- Outbound requests: `NewClient`, `NewClientRequest`, `GetJSON`, `PostJSON`, `Do`

## Notes

- Resty v3 is currently beta and imported via `resty.dev/v3`.
- Keep this package transport-focused; put service-specific API shapes in domain adapters (for example, `internal/ti/whois_client.go`).
