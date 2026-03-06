package httputil

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	resty "resty.dev/v3"
)

const (
	DefaultClientTimeout      = 15 * time.Second
	DefaultClientRetryCount   = 2
	DefaultClientRetryWait    = 250 * time.Millisecond
	DefaultClientRetryMaxWait = 2 * time.Second
)

type Client interface {
	Do(ctx context.Context, req *ClientRequest, out any) (*ClientResponse, error)
	GetJSON(ctx context.Context, url string, out any, opts ...ClientRequestOption) (*ClientResponse, error)
	PostJSON(ctx context.Context, url string, body any, out any, opts ...ClientRequestOption) (*ClientResponse, error)
}

type ClientRequest struct {
	Method         string
	URL            string
	Headers        map[string]string
	QueryParams    map[string]string
	PathParams     map[string]string
	Body           any
	Timeout        time.Duration
	ExpectedStatus []int
}

type ClientResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

type ClientError struct {
	Method       string
	URL          string
	StatusCode   int
	Message      string
	ResponseBody string
	Err          error
}

func (e *ClientError) Error() string {
	if e == nil {
		return ""
	}

	var builder strings.Builder

	message := strings.TrimSpace(e.Message)
	if message == "" {
		message = "outbound request failed"
	}
	builder.WriteString(message)

	if e.Method != "" {
		builder.WriteString(" method=")
		builder.WriteString(e.Method)
	}

	if e.URL != "" {
		builder.WriteString(" url=")
		builder.WriteString(e.URL)
	}

	if e.StatusCode > 0 {
		builder.WriteString(" status=")
		builder.WriteString(fmt.Sprintf("%d", e.StatusCode))
	}

	if strings.TrimSpace(e.ResponseBody) != "" {
		builder.WriteString(" response=")
		builder.WriteString(e.ResponseBody)
	}

	if e.Err != nil {
		builder.WriteString(": ")
		builder.WriteString(e.Err.Error())
	}

	return builder.String()
}

func (e *ClientError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

type ClientOption func(*resty.Client)

type ClientRequestOption func(*ClientRequest)

func NewClient(opts ...ClientOption) Client {
	client := resty.New()

	client.SetTimeout(DefaultClientTimeout)
	client.SetRetryCount(DefaultClientRetryCount)
	client.SetRetryWaitTime(DefaultClientRetryWait)
	client.SetRetryMaxWaitTime(DefaultClientRetryMaxWait)
	client.SetHeader("Accept", "application/json")

	client.AddRetryConditions(shouldRetryRequest)

	for _, opt := range opts {
		if opt != nil {
			opt(client)
		}
	}

	return &restyClient{client: client}
}

func shouldRetryRequest(response *resty.Response, err error) bool {
	if err != nil {
		return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
	}

	if response == nil {
		return false
	}

	statusCode := response.StatusCode()
	return statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError
}

func WithClientBaseURL(baseURL string) ClientOption {
	return func(client *resty.Client) {
		baseURL = strings.TrimSpace(baseURL)
		if baseURL != "" {
			client.SetBaseURL(baseURL)
		}
	}
}

func WithClientTimeout(timeout time.Duration) ClientOption {
	return func(client *resty.Client) {
		if timeout > 0 {
			client.SetTimeout(timeout)
		}
	}
}

func WithClientRetry(count int, wait, maxWait time.Duration) ClientOption {
	return func(client *resty.Client) {
		if count >= 0 {
			client.SetRetryCount(count)
		}

		if wait > 0 {
			client.SetRetryWaitTime(wait)
		}

		if maxWait > 0 {
			client.SetRetryMaxWaitTime(maxWait)
		}
	}
}

func WithClientHeader(key, value string) ClientOption {
	return func(client *resty.Client) {
		key = strings.TrimSpace(key)
		if key == "" {
			return
		}

		client.SetHeader(key, value)
	}
}

func NewClientRequest(method, url string, opts ...ClientRequestOption) *ClientRequest {
	req := &ClientRequest{
		Method:      method,
		URL:         url,
		Headers:     map[string]string{},
		QueryParams: map[string]string{},
		PathParams:  map[string]string{},
	}

	for _, opt := range opts {
		if opt != nil {
			opt(req)
		}
	}

	return req
}

func WithClientRequestHeader(key, value string) ClientRequestOption {
	return func(req *ClientRequest) {
		if req == nil {
			return
		}

		key = strings.TrimSpace(key)
		if key == "" {
			return
		}

		if req.Headers == nil {
			req.Headers = map[string]string{}
		}

		req.Headers[key] = value
	}
}

func WithClientRequestHeaders(headers map[string]string) ClientRequestOption {
	return func(req *ClientRequest) {
		if req == nil || len(headers) == 0 {
			return
		}

		if req.Headers == nil {
			req.Headers = map[string]string{}
		}

		for key, value := range headers {
			trimmed := strings.TrimSpace(key)
			if trimmed != "" {
				req.Headers[trimmed] = value
			}
		}
	}
}

func WithClientRequestQueryParam(key, value string) ClientRequestOption {
	return func(req *ClientRequest) {
		if req == nil {
			return
		}

		key = strings.TrimSpace(key)
		if key == "" {
			return
		}

		if req.QueryParams == nil {
			req.QueryParams = map[string]string{}
		}

		req.QueryParams[key] = value
	}
}

func WithClientRequestQueryParams(queryParams map[string]string) ClientRequestOption {
	return func(req *ClientRequest) {
		if req == nil || len(queryParams) == 0 {
			return
		}

		if req.QueryParams == nil {
			req.QueryParams = map[string]string{}
		}

		for key, value := range queryParams {
			trimmed := strings.TrimSpace(key)
			if trimmed != "" {
				req.QueryParams[trimmed] = value
			}
		}
	}
}

func WithClientRequestPathParam(key, value string) ClientRequestOption {
	return func(req *ClientRequest) {
		if req == nil {
			return
		}

		key = strings.TrimSpace(key)
		if key == "" {
			return
		}

		if req.PathParams == nil {
			req.PathParams = map[string]string{}
		}

		req.PathParams[key] = value
	}
}

func WithClientRequestPathParams(pathParams map[string]string) ClientRequestOption {
	return func(req *ClientRequest) {
		if req == nil || len(pathParams) == 0 {
			return
		}

		if req.PathParams == nil {
			req.PathParams = map[string]string{}
		}

		for key, value := range pathParams {
			trimmed := strings.TrimSpace(key)
			if trimmed != "" {
				req.PathParams[trimmed] = value
			}
		}
	}
}

func WithClientRequestBody(body any) ClientRequestOption {
	return func(req *ClientRequest) {
		if req == nil {
			return
		}

		req.Body = body
	}
}

func WithClientRequestExpectedStatus(statusCodes ...int) ClientRequestOption {
	return func(req *ClientRequest) {
		if req == nil {
			return
		}

		if len(statusCodes) == 0 {
			req.ExpectedStatus = nil
			return
		}

		req.ExpectedStatus = append([]int(nil), statusCodes...)
	}
}

func WithClientRequestTimeout(timeout time.Duration) ClientRequestOption {
	return func(req *ClientRequest) {
		if req == nil {
			return
		}

		req.Timeout = timeout
	}
}

type restyClient struct {
	client *resty.Client
}

func (c *restyClient) GetJSON(ctx context.Context, url string, out any, opts ...ClientRequestOption) (*ClientResponse, error) {
	req := NewClientRequest(http.MethodGet, url, opts...)
	return c.Do(ctx, req, out)
}

func (c *restyClient) PostJSON(ctx context.Context, url string, body any, out any, opts ...ClientRequestOption) (*ClientResponse, error) {
	requestOpts := make([]ClientRequestOption, 0, len(opts)+1)
	requestOpts = append(requestOpts, WithClientRequestBody(body))
	requestOpts = append(requestOpts, opts...)

	req := NewClientRequest(http.MethodPost, url, requestOpts...)
	return c.Do(ctx, req, out)
}

func (c *restyClient) Do(ctx context.Context, req *ClientRequest, out any) (*ClientResponse, error) {
	if req == nil {
		return nil, &ClientError{Message: "request must not be nil"}
	}

	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		return nil, &ClientError{Message: "request method must not be empty"}
	}

	requestURL := strings.TrimSpace(req.URL)
	if requestURL == "" {
		return nil, &ClientError{Method: method, Message: "request URL must not be empty"}
	}

	restRequest := c.client.R()

	requestContext := ctx
	if requestContext == nil {
		requestContext = context.Background()
	}

	if req.Timeout > 0 {
		timeoutContext, cancel := context.WithTimeout(requestContext, req.Timeout)
		defer cancel()
		requestContext = timeoutContext
	}

	restRequest.SetContext(requestContext)

	for key, value := range req.Headers {
		trimmed := strings.TrimSpace(key)
		if trimmed != "" {
			restRequest.SetHeader(trimmed, value)
		}
	}

	if req.Body != nil {
		restRequest.SetBody(req.Body)

		hasContentType := false
		for key := range req.Headers {
			if strings.EqualFold(strings.TrimSpace(key), "Content-Type") {
				hasContentType = true
				break
			}
		}

		if !hasContentType {
			restRequest.SetHeader("Content-Type", "application/json")
		}
	}

	if len(req.QueryParams) > 0 {
		restRequest.SetQueryParams(req.QueryParams)
	}

	if len(req.PathParams) > 0 {
		restRequest.SetPathParams(req.PathParams)
	}

	if out != nil {
		restRequest.SetResult(out)
	}

	response, err := restRequest.Execute(method, requestURL)
	if err != nil {
		return nil, &ClientError{
			Method:  method,
			URL:     requestURL,
			Message: "outbound request failed",
			Err:     err,
		}
	}

	clientResponse := &ClientResponse{
		StatusCode: response.StatusCode(),
		Headers:    cloneHeader(response.Header()),
		Body:       append([]byte(nil), response.Bytes()...),
	}

	if !isExpectedStatus(response.StatusCode(), req.ExpectedStatus) {
		return clientResponse, &ClientError{
			Method:       method,
			URL:          requestURL,
			StatusCode:   response.StatusCode(),
			Message:      fmt.Sprintf("unexpected status code %d", response.StatusCode()),
			ResponseBody: truncateString(string(response.Bytes()), 2048),
		}
	}

	return clientResponse, nil
}

func isExpectedStatus(statusCode int, expectedStatus []int) bool {
	if len(expectedStatus) == 0 {
		return statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices
	}

	for _, code := range expectedStatus {
		if code == statusCode {
			return true
		}
	}

	return false
}

func cloneHeader(header http.Header) http.Header {
	if header == nil {
		return nil
	}

	clone := make(http.Header, len(header))
	for key, values := range header {
		clone[key] = append([]string(nil), values...)
	}

	return clone
}

func truncateString(value string, maxLen int) string {
	value = strings.TrimSpace(value)
	if maxLen <= 0 || len(value) <= maxLen {
		return value
	}

	if maxLen <= 3 {
		return value[:maxLen]
	}

	return value[:maxLen-3] + "..."
}
