package httputil

import (
	"bytes"
	stdctx "context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	JSONContentType                  = "application/json; charset=utf-8"
	DefaultMaxRequestBodyBytes int64 = 1 << 20
	DefaultServerListenAddr          = ":8080"
)

type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

type APIError struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

type ErrorResponse struct {
	Success bool     `json:"success"`
	Error   APIError `json:"error"`
}

type RequestError struct {
	Status  int
	Code    string
	Message string
	Details any
	Err     error
}

type Validatable interface {
	Validate() error
}

type Context interface {
	Request() *http.Request
	Writer() http.ResponseWriter

	Param(key string) string
	Query(key string) string
	Header(key string) string

	Set(key string, value any)
	Get(key string) (any, bool)

	Next()
	Abort()
	AbortWithStatus(statusCode int)

	ParseJSON(dst any) *RequestError
	ParseJSONWithLimit(dst any, maxBodyBytes int64) *RequestError
	ParseAndValidateJSON(dst Validatable) *RequestError

	JSON(statusCode int, payload any) error
	Success(statusCode int, data any) error
	SuccessMessage(statusCode int, message string, data any) error
	OK(data any) error
	Created(data any) error
	Error(statusCode int, code, message string) error
	ErrorWithDetails(statusCode int, code, message string, details any) error
	RequestError(err *RequestError) error
}

type HandlerFunc func(Context)

type MiddlewareFunc func(Context)

type Router interface {
	Use(middleware ...MiddlewareFunc)
	GET(path string, handlers ...HandlerFunc)
	POST(path string, handlers ...HandlerFunc)
	PUT(path string, handlers ...HandlerFunc)
	PATCH(path string, handlers ...HandlerFunc)
	DELETE(path string, handlers ...HandlerFunc)
	Group(prefix string, middleware ...MiddlewareFunc) Router
}

type Server interface {
	Router
	Start(addr string) error
	Shutdown(ctx stdctx.Context) error
	Engine() *gin.Engine
}

func NewServer() Server {
	engine := gin.New()
	engine.Use(gin.Recovery())

	return &ginServer{
		engine: engine,
		server: &http.Server{Handler: engine},
	}
}

func NewDefaultServer() Server {
	engine := gin.Default()

	return &ginServer{
		engine: engine,
		server: &http.Server{Handler: engine},
	}
}

type ginServer struct {
	engine *gin.Engine
	server *http.Server
}

func (s *ginServer) Start(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = DefaultServerListenAddr
	}

	s.server.Addr = addr

	err := s.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return err
}

func (s *ginServer) Shutdown(ctx stdctx.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *ginServer) Engine() *gin.Engine {
	return s.engine
}

func (s *ginServer) Use(middleware ...MiddlewareFunc) {
	if len(middleware) == 0 {
		return
	}

	s.engine.Use(wrapMiddleware(middleware)...)
}

func (s *ginServer) GET(path string, handlers ...HandlerFunc) {
	s.engine.GET(path, wrapHandlers(handlers)...)
}

func (s *ginServer) POST(path string, handlers ...HandlerFunc) {
	s.engine.POST(path, wrapHandlers(handlers)...)
}

func (s *ginServer) PUT(path string, handlers ...HandlerFunc) {
	s.engine.PUT(path, wrapHandlers(handlers)...)
}

func (s *ginServer) PATCH(path string, handlers ...HandlerFunc) {
	s.engine.PATCH(path, wrapHandlers(handlers)...)
}

func (s *ginServer) DELETE(path string, handlers ...HandlerFunc) {
	s.engine.DELETE(path, wrapHandlers(handlers)...)
}

func (s *ginServer) Group(prefix string, middleware ...MiddlewareFunc) Router {
	if len(middleware) == 0 {
		return &ginRouterGroup{group: s.engine.Group(prefix)}
	}

	return &ginRouterGroup{group: s.engine.Group(prefix, wrapMiddleware(middleware)...)}
}

type ginRouterGroup struct {
	group *gin.RouterGroup
}

func (g *ginRouterGroup) Use(middleware ...MiddlewareFunc) {
	if len(middleware) == 0 {
		return
	}

	g.group.Use(wrapMiddleware(middleware)...)
}

func (g *ginRouterGroup) GET(path string, handlers ...HandlerFunc) {
	g.group.GET(path, wrapHandlers(handlers)...)
}

func (g *ginRouterGroup) POST(path string, handlers ...HandlerFunc) {
	g.group.POST(path, wrapHandlers(handlers)...)
}

func (g *ginRouterGroup) PUT(path string, handlers ...HandlerFunc) {
	g.group.PUT(path, wrapHandlers(handlers)...)
}

func (g *ginRouterGroup) PATCH(path string, handlers ...HandlerFunc) {
	g.group.PATCH(path, wrapHandlers(handlers)...)
}

func (g *ginRouterGroup) DELETE(path string, handlers ...HandlerFunc) {
	g.group.DELETE(path, wrapHandlers(handlers)...)
}

func (g *ginRouterGroup) Group(prefix string, middleware ...MiddlewareFunc) Router {
	if len(middleware) == 0 {
		return &ginRouterGroup{group: g.group.Group(prefix)}
	}

	return &ginRouterGroup{group: g.group.Group(prefix, wrapMiddleware(middleware)...)}
}

type ginContextAdapter struct {
	ctx *gin.Context
}

func (c *ginContextAdapter) Request() *http.Request {
	return c.ctx.Request
}

func (c *ginContextAdapter) Writer() http.ResponseWriter {
	return c.ctx.Writer
}

func (c *ginContextAdapter) Param(key string) string {
	return c.ctx.Param(key)
}

func (c *ginContextAdapter) Query(key string) string {
	return c.ctx.Query(key)
}

func (c *ginContextAdapter) Header(key string) string {
	return c.ctx.GetHeader(key)
}

func (c *ginContextAdapter) Set(key string, value any) {
	c.ctx.Set(key, value)
}

func (c *ginContextAdapter) Get(key string) (any, bool) {
	return c.ctx.Get(key)
}

func (c *ginContextAdapter) Next() {
	c.ctx.Next()
}

func (c *ginContextAdapter) Abort() {
	c.ctx.Abort()
}

func (c *ginContextAdapter) AbortWithStatus(statusCode int) {
	c.ctx.AbortWithStatus(statusCode)
}

func (c *ginContextAdapter) ParseJSON(dst any) *RequestError {
	return ParseJSON(c.ctx.Request, dst)
}

func (c *ginContextAdapter) ParseJSONWithLimit(dst any, maxBodyBytes int64) *RequestError {
	return ParseJSONWithLimit(c.ctx.Request, dst, maxBodyBytes)
}

func (c *ginContextAdapter) ParseAndValidateJSON(dst Validatable) *RequestError {
	return ParseAndValidateJSON(c.ctx.Request, dst)
}

func (c *ginContextAdapter) JSON(statusCode int, payload any) error {
	return WriteJSON(c.ctx.Writer, statusCode, payload)
}

func (c *ginContextAdapter) Success(statusCode int, data any) error {
	return WriteSuccess(c.ctx.Writer, statusCode, data)
}

func (c *ginContextAdapter) SuccessMessage(statusCode int, message string, data any) error {
	return WriteSuccessMessage(c.ctx.Writer, statusCode, message, data)
}

func (c *ginContextAdapter) OK(data any) error {
	return WriteOK(c.ctx.Writer, data)
}

func (c *ginContextAdapter) Created(data any) error {
	return WriteCreated(c.ctx.Writer, data)
}

func (c *ginContextAdapter) Error(statusCode int, code, message string) error {
	return WriteError(c.ctx.Writer, statusCode, code, message)
}

func (c *ginContextAdapter) ErrorWithDetails(statusCode int, code, message string, details any) error {
	return WriteErrorWithDetails(c.ctx.Writer, statusCode, code, message, details)
}

func (c *ginContextAdapter) RequestError(err *RequestError) error {
	return WriteRequestError(c.ctx.Writer, err)
}

func wrapHandlers(handlers []HandlerFunc) []gin.HandlerFunc {
	wrapped := make([]gin.HandlerFunc, 0, len(handlers))

	for _, handler := range handlers {
		h := handler
		wrapped = append(wrapped, func(ctx *gin.Context) {
			h(&ginContextAdapter{ctx: ctx})
		})
	}

	return wrapped
}

func wrapMiddleware(middleware []MiddlewareFunc) []gin.HandlerFunc {
	wrapped := make([]gin.HandlerFunc, 0, len(middleware))

	for _, handler := range middleware {
		h := handler
		wrapped = append(wrapped, func(ctx *gin.Context) {
			h(&ginContextAdapter{ctx: ctx})
		})
	}

	return wrapped
}

func (e *RequestError) Error() string {
	if e == nil {
		return ""
	}

	if message := strings.TrimSpace(e.Message); message != "" {
		return message
	}

	if e.Err != nil {
		return e.Err.Error()
	}

	if status := http.StatusText(e.Status); status != "" {
		return status
	}

	return "request failed"
}

func (e *RequestError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

func NewRequestError(status int, code, message string, details any, err error) *RequestError {
	if status < 100 || status > 999 {
		status = http.StatusBadRequest
	}

	message = strings.TrimSpace(message)
	if message == "" && err != nil {
		message = err.Error()
	}

	return &RequestError{
		Status:  status,
		Code:    normalizeErrorCode(status, code),
		Message: normalizeErrorMessage(status, message),
		Details: details,
		Err:     err,
	}
}

func ParseJSON(r *http.Request, dst any) *RequestError {
	return ParseJSONWithLimit(r, dst, DefaultMaxRequestBodyBytes)
}

func ParseJSONWithLimit(r *http.Request, dst any, maxBodyBytes int64) *RequestError {
	if r == nil {
		return NewRequestError(http.StatusBadRequest, "bad_request", "request cannot be nil", nil, nil)
	}

	if err := ensureDecodeTarget(dst); err != nil {
		return err
	}

	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxRequestBodyBytes
	}

	if err := validateJSONContentType(r.Header.Get("Content-Type")); err != nil {
		return err
	}

	if r.Body == nil {
		return NewRequestError(http.StatusBadRequest, "empty_body", "request body must not be empty", nil, nil)
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return NewRequestError(http.StatusBadRequest, "invalid_body", "unable to read request body", nil, err)
	}

	if int64(len(body)) > maxBodyBytes {
		return NewRequestError(
			http.StatusRequestEntityTooLarge,
			"body_too_large",
			fmt.Sprintf("request body exceeds %d bytes", maxBodyBytes),
			map[string]any{"max_bytes": maxBodyBytes},
			nil,
		)
	}

	if len(bytes.TrimSpace(body)) == 0 {
		return NewRequestError(http.StatusBadRequest, "empty_body", "request body must not be empty", nil, nil)
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return normalizeJSONDecodeError(err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return NewRequestError(
			http.StatusBadRequest,
			"invalid_json",
			"request body must contain only a single JSON object",
			nil,
			err,
		)
	}

	return nil
}

func ParseAndValidateJSON(r *http.Request, dst Validatable) *RequestError {
	if isNilValue(dst) {
		return NewRequestError(http.StatusBadRequest, "invalid_request", "request payload must not be nil", nil, nil)
	}

	if err := ParseJSON(r, dst); err != nil {
		return err
	}

	if err := dst.Validate(); err != nil {
		return NewRequestError(http.StatusUnprocessableEntity, "validation_failed", err.Error(), nil, err)
	}

	return nil
}

func ParseAndValidateJSONWith[T any](r *http.Request, dst *T, validator func(*T) error) *RequestError {
	if err := ParseJSON(r, dst); err != nil {
		return err
	}

	return ValidateWith(dst, validator)
}

func ValidateWith[T any](dst *T, validator func(*T) error) *RequestError {
	if dst == nil {
		return NewRequestError(http.StatusBadRequest, "invalid_request", "request payload must not be nil", nil, nil)
	}

	if validator == nil {
		return nil
	}

	if err := validator(dst); err != nil {
		return NewRequestError(http.StatusUnprocessableEntity, "validation_failed", err.Error(), nil, err)
	}

	return nil
}

func WriteJSON(w http.ResponseWriter, statusCode int, payload any) error {
	if statusCode < 100 || statusCode > 999 {
		statusCode = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", JSONContentType)
	w.WriteHeader(statusCode)

	if payload == nil {
		return nil
	}

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(payload); err != nil {
		return fmt.Errorf("encode json response: %w", err)
	}

	return nil
}

func WriteSuccess(w http.ResponseWriter, statusCode int, data any) error {
	return WriteSuccessMessage(w, statusCode, "", data)
}

func WriteSuccessMessage(w http.ResponseWriter, statusCode int, message string, data any) error {
	return WriteJSON(w, statusCode, SuccessResponse{
		Success: true,
		Message: strings.TrimSpace(message),
		Data:    data,
	})
}

func WriteOK(w http.ResponseWriter, data any) error {
	return WriteSuccess(w, http.StatusOK, data)
}

func WriteCreated(w http.ResponseWriter, data any) error {
	return WriteSuccess(w, http.StatusCreated, data)
}

func WriteStatusError(w http.ResponseWriter, statusCode int) error {
	return WriteError(w, statusCode, "", "")
}

func WriteError(w http.ResponseWriter, statusCode int, code, message string) error {
	return WriteErrorWithDetails(w, statusCode, code, message, nil)
}

func WriteErrorWithDetails(w http.ResponseWriter, statusCode int, code, message string, details any) error {
	return WriteJSON(w, statusCode, ErrorResponse{
		Success: false,
		Error: APIError{
			Status:  statusCode,
			Code:    normalizeErrorCode(statusCode, code),
			Message: normalizeErrorMessage(statusCode, message),
			Details: details,
		},
	})
}

func WriteRequestError(w http.ResponseWriter, reqErr *RequestError) error {
	if reqErr == nil {
		return WriteStatusError(w, http.StatusBadRequest)
	}

	return WriteErrorWithDetails(w, reqErr.Status, reqErr.Code, reqErr.Message, reqErr.Details)
}

func normalizeErrorMessage(statusCode int, message string) string {
	message = strings.TrimSpace(message)
	if message != "" {
		return message
	}

	if status := http.StatusText(statusCode); status != "" {
		return status
	}

	return "request failed"
}

func normalizeErrorCode(statusCode int, code string) string {
	code = strings.TrimSpace(code)
	if code != "" {
		return code
	}

	switch statusCode {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusUnsupportedMediaType:
		return "unsupported_media_type"
	case http.StatusUnprocessableEntity:
		return "validation_failed"
	case http.StatusTooManyRequests:
		return "too_many_requests"
	case http.StatusInternalServerError:
		return "internal_error"
	case http.StatusServiceUnavailable:
		return "service_unavailable"
	default:
		return "error"
	}
}

func ensureDecodeTarget(dst any) *RequestError {
	if dst == nil {
		return NewRequestError(
			http.StatusInternalServerError,
			"internal_error",
			"decode destination must be a non-nil pointer",
			nil,
			nil,
		)
	}

	value := reflect.ValueOf(dst)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return NewRequestError(
			http.StatusInternalServerError,
			"internal_error",
			"decode destination must be a non-nil pointer",
			nil,
			nil,
		)
	}

	return nil
}

func validateJSONContentType(contentType string) *RequestError {
	if strings.TrimSpace(contentType) == "" {
		return nil
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return NewRequestError(http.StatusBadRequest, "invalid_content_type", "invalid Content-Type header", nil, err)
	}

	if mediaType != "application/json" {
		return NewRequestError(
			http.StatusUnsupportedMediaType,
			"unsupported_media_type",
			"Content-Type must be application/json",
			map[string]any{"content_type": mediaType},
			nil,
		)
	}

	return nil
}

func normalizeJSONDecodeError(err error) *RequestError {
	var syntaxError *json.SyntaxError
	var unmarshalTypeError *json.UnmarshalTypeError

	switch {
	case errors.As(err, &syntaxError):
		return NewRequestError(
			http.StatusBadRequest,
			"invalid_json",
			fmt.Sprintf("request body contains malformed JSON at position %d", syntaxError.Offset),
			nil,
			err,
		)
	case errors.Is(err, io.ErrUnexpectedEOF):
		return NewRequestError(http.StatusBadRequest, "invalid_json", "request body contains malformed JSON", nil, err)
	case errors.As(err, &unmarshalTypeError):
		if unmarshalTypeError.Field != "" {
			return NewRequestError(
				http.StatusBadRequest,
				"invalid_field_type",
				fmt.Sprintf("request body field %q must be %s", unmarshalTypeError.Field, unmarshalTypeError.Type),
				map[string]any{
					"field":    unmarshalTypeError.Field,
					"expected": unmarshalTypeError.Type.String(),
				},
				err,
			)
		}

		return NewRequestError(http.StatusBadRequest, "invalid_field_type", "request body contains an invalid value type", nil, err)
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		field := strings.TrimPrefix(err.Error(), "json: unknown field ")
		return NewRequestError(
			http.StatusBadRequest,
			"unknown_field",
			fmt.Sprintf("request body contains unknown field %s", field),
			map[string]any{"field": strings.Trim(field, "\"")},
			err,
		)
	case errors.Is(err, io.EOF):
		return NewRequestError(http.StatusBadRequest, "empty_body", "request body must not be empty", nil, err)
	default:
		return NewRequestError(http.StatusBadRequest, "invalid_json", "request body contains invalid JSON", nil, err)
	}
}

func isNilValue(value any) bool {
	if value == nil {
		return true
	}

	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
