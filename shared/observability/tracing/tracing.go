package tracing

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

func Init(ctx context.Context, serviceName, jaegerEndpoint string) (func(context.Context) error, error) {
	endpoint := strings.TrimSpace(jaegerEndpoint)
	if endpoint == "" {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		))
		return func(context.Context) error { return nil }, nil
	}

	if strings.TrimSpace(serviceName) == "" {
		serviceName = "cybersiren"
	}

	opts, err := exporterOptions(endpoint)
	if err != nil {
		return nil, err
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating trace resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}

func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

func exporterOptions(rawEndpoint string) ([]otlptracehttp.Option, error) {
	if strings.Contains(rawEndpoint, "://") {
		u, err := url.Parse(rawEndpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid jaeger endpoint %q: %w", rawEndpoint, err)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("invalid jaeger endpoint %q: missing host", rawEndpoint)
		}

		opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(u.Host)}
		if u.Path != "" && u.Path != "/" {
			opts = append(opts, otlptracehttp.WithURLPath(u.Path))
		}

		switch u.Scheme {
		case "http":
			opts = append(opts, otlptracehttp.WithInsecure())
		case "https":
			// secure by default
		default:
			return nil, fmt.Errorf("invalid jaeger endpoint %q: unsupported scheme %q", rawEndpoint, u.Scheme)
		}

		return opts, nil
	}

	return []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(rawEndpoint),
		otlptracehttp.WithInsecure(),
	}, nil
}
