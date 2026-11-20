#![forbid(unsafe_code)]

//! OpenTelemetry traces, structured JSON logs with trace/span IDs, and
//! Prometheus + OTLP metrics exposition for Operquay-Rust.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, MeterProvider as _, UpDownCounter};
use opentelemetry::trace::{TraceContextExt, TracerProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use opentelemetry_sdk::{metrics::SdkMeterProvider, Resource};
use prometheus::{Encoder, Registry, TextEncoder};
use serde::Serialize;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Serialize)]
pub struct TelemetrySummary {
    pub service_name: String,
    pub otlp_configured: bool,
    pub sessions_started_total: u64,
    pub active_sessions: i64,
    pub frames_encoded_total: u64,
    pub frames_dropped_total: u64,
    pub settings_updates_total: u64,
    pub db_queries_total: u64,
    pub ssm_tunnels_total: u64,
    pub auth_events_total: u64,
    pub k8s_requests_total: u64,
    pub ai_requests_total: u64,
    pub last_frame_encode_ms: f64,
    pub last_input_rtt_ms: f64,
}

pub struct TelemetryHub {
    service_name: String,
    otlp_configured: bool,
    prom_registry: Registry,
    _tracer_provider: SdkTracerProvider,
    _meter_provider: SdkMeterProvider,
    sessions_started_metric: Counter<u64>,
    active_sessions_metric: UpDownCounter<i64>,
    frames_encoded_metric: Counter<u64>,
    frames_dropped_metric: Counter<u64>,
    settings_updates_metric: Counter<u64>,
    db_queries_metric: Counter<u64>,
    db_query_duration_hist: Histogram<f64>,
    ssm_tunnels_metric: Counter<u64>,
    auth_events_metric: Counter<u64>,
    k8s_requests_metric: Counter<u64>,
    ai_requests_metric: Counter<u64>,
    frame_encode_hist: Histogram<f64>,
    input_rtt_hist: Histogram<f64>,
    sessions_started_atom: AtomicU64,
    active_sessions_atom: AtomicI64,
    frames_encoded_atom: AtomicU64,
    frames_dropped_atom: AtomicU64,
    settings_updates_atom: AtomicU64,
    db_queries_atom: AtomicU64,
    ssm_tunnels_atom: AtomicU64,
    auth_events_atom: AtomicU64,
    k8s_requests_atom: AtomicU64,
    ai_requests_atom: AtomicU64,
    last_encode_us: AtomicU64,
    last_rtt_us: AtomicU64,
}

impl TelemetryHub {
    /// Build an OpenTelemetry tracer + Prometheus-bridged meter provider.
    /// When `otlp_endpoint` is `Some`, spans also export asynchronously via OTLP gRPC.
    #[must_use]
    pub fn build(
        service_name: &str,
        otlp_endpoint: Option<&str>,
        sample_ratio: f64,
        install_global_subscriber: bool,
    ) -> Arc<Self> {
        global::set_text_map_propagator(TraceContextPropagator::new());

        let resource = Resource::builder()
            .with_attributes([
                KeyValue::new("service.name", service_name.to_owned()),
                KeyValue::new("service.version", env!("CARGO_PKG_VERSION").to_owned()),
            ])
            .build();

        let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            sample_ratio.clamp(0.0, 1.0),
        )));

        let mut trace_builder = SdkTracerProvider::builder()
            .with_resource(resource.clone())
            .with_id_generator(RandomIdGenerator::default())
            .with_sampler(sampler);

        let mut otlp_configured = false;
        if let Some(endpoint) = otlp_endpoint.filter(|s| !s.trim().is_empty()) {
            if let Ok(exporter) = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()
            {
                trace_builder = trace_builder.with_batch_exporter(exporter);
                otlp_configured = true;
            }
        }

        let tracer_provider = trace_builder.build();
        let tracer = tracer_provider.tracer("operquay-rust");

        let prom_registry = Registry::new();
        let prom_exporter = opentelemetry_prometheus::exporter()
            .with_registry(prom_registry.clone())
            .build()
            .expect("prometheus exporter initialization should succeed");

        let meter_provider = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_reader(prom_exporter)
            .build();

        let meter = meter_provider.meter("operquay-rust");

        if install_global_subscriber {
            let filter = EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,operquay=debug,tower_http=info"));
            let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            let fmt_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(false);

            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(otel_layer)
                .with(fmt_layer)
                .try_init();
        }

        global::set_tracer_provider(tracer_provider.clone());

        Arc::new(Self {
            service_name: service_name.to_owned(),
            otlp_configured,
            prom_registry,
            _tracer_provider: tracer_provider,
            _meter_provider: meter_provider,
            sessions_started_metric: meter
                .u64_counter("operquay_sessions_started")
                .with_description("Total remote desktop sessions started")
                .build(),
            active_sessions_metric: meter
                .i64_up_down_counter("operquay_active_sessions")
                .with_description("Currently open remote desktop sessions")
                .build(),
            frames_encoded_metric: meter
                .u64_counter("operquay_frames_encoded")
                .with_description("Display frames/tiles encoded and queued")
                .build(),
            frames_dropped_metric: meter
                .u64_counter("operquay_frames_dropped")
                .with_description("Display frames dropped by congestion pacing")
                .build(),
            settings_updates_metric: meter
                .u64_counter("operquay_settings_updates")
                .with_description("Settings profile updates persisted")
                .build(),
            db_queries_metric: meter
                .u64_counter("operquay_db_queries")
                .with_description("Database workspace queries and mutations executed")
                .build(),
            db_query_duration_hist: meter
                .f64_histogram("operquay_db_query_duration_ms")
                .with_description("Database workspace query execution latency in milliseconds")
                .build(),
            ssm_tunnels_metric: meter
                .u64_counter("operquay_ssm_tunnels")
                .with_description("AWS SSM port-forward and desktop tunnels opened")
                .build(),
            auth_events_metric: meter
                .u64_counter("operquay_auth_events")
                .with_description("Authentication, OIDC, and SCIM security events")
                .build(),
            k8s_requests_metric: meter
                .u64_counter("operquay_k8s_requests")
                .with_description("Kubernetes cluster API operations")
                .build(),
            ai_requests_metric: meter
                .u64_counter("operquay_ai_requests")
                .with_description("AI copilot chat and safety classification calls")
                .build(),
            frame_encode_hist: meter
                .f64_histogram("operquay_frame_encode_duration_ms")
                .with_description("Duration of display frame planning and encoding in milliseconds")
                .build(),
            input_rtt_hist: meter
                .f64_histogram("operquay_input_rtt_ms")
                .with_description(
                    "Observed client-to-server input round-trip latency in milliseconds",
                )
                .build(),
            sessions_started_atom: AtomicU64::new(0),
            active_sessions_atom: AtomicI64::new(0),
            frames_encoded_atom: AtomicU64::new(0),
            frames_dropped_atom: AtomicU64::new(0),
            settings_updates_atom: AtomicU64::new(0),
            db_queries_atom: AtomicU64::new(0),
            ssm_tunnels_atom: AtomicU64::new(0),
            auth_events_atom: AtomicU64::new(0),
            k8s_requests_atom: AtomicU64::new(0),
            ai_requests_atom: AtomicU64::new(0),
            last_encode_us: AtomicU64::new(0),
            last_rtt_us: AtomicU64::new(0),
        })
    }

    pub fn record_session_started(&self, protocol: &str, preset: &str) {
        self.sessions_started_atom.fetch_add(1, Ordering::Relaxed);
        self.active_sessions_atom.fetch_add(1, Ordering::Relaxed);
        let attrs = [
            KeyValue::new("protocol", protocol.to_owned()),
            KeyValue::new("preset", preset.to_owned()),
        ];
        self.sessions_started_metric.add(1, &attrs);
        self.active_sessions_metric
            .add(1, &[KeyValue::new("protocol", protocol.to_owned())]);
    }

    pub fn record_session_ended(&self, protocol: &str) {
        self.active_sessions_atom.fetch_sub(1, Ordering::Relaxed);
        self.active_sessions_metric
            .add(-1, &[KeyValue::new("protocol", protocol.to_owned())]);
    }

    pub fn record_frame_encoded(&self, codec: &str, encode_ms: f64) {
        self.frames_encoded_atom.fetch_add(1, Ordering::Relaxed);
        self.last_encode_us
            .store((encode_ms * 1000.0).max(0.0) as u64, Ordering::Relaxed);
        self.frames_encoded_metric
            .add(1, &[KeyValue::new("codec", codec.to_owned())]);
        self.frame_encode_hist
            .record(encode_ms, &[KeyValue::new("codec", codec.to_owned())]);
    }

    pub fn record_frame_dropped(&self, reason: &str) {
        self.frames_dropped_atom.fetch_add(1, Ordering::Relaxed);
        self.frames_dropped_metric
            .add(1, &[KeyValue::new("reason", reason.to_owned())]);
    }

    pub fn record_input_rtt(&self, protocol: &str, rtt_ms: f64) {
        self.last_rtt_us
            .store((rtt_ms * 1000.0).max(0.0) as u64, Ordering::Relaxed);
        self.input_rtt_hist
            .record(rtt_ms, &[KeyValue::new("protocol", protocol.to_owned())]);
    }

    pub fn record_settings_update(&self, preset: &str) {
        self.settings_updates_atom.fetch_add(1, Ordering::Relaxed);
        self.settings_updates_metric
            .add(1, &[KeyValue::new("preset", preset.to_owned())]);
    }

    pub fn record_db_query(&self, engine: &str, status: &str, duration_ms: f64) {
        self.db_queries_atom.fetch_add(1, Ordering::Relaxed);
        self.db_queries_metric.add(
            1,
            &[
                KeyValue::new("engine", engine.to_owned()),
                KeyValue::new("status", status.to_owned()),
            ],
        );
        self.db_query_duration_hist.record(
            duration_ms.max(0.0),
            &[KeyValue::new("engine", engine.to_owned())],
        );
    }

    pub fn record_ssm_tunnel(&self, protocol: &str, status: &str) {
        self.ssm_tunnels_atom.fetch_add(1, Ordering::Relaxed);
        self.ssm_tunnels_metric.add(
            1,
            &[
                KeyValue::new("protocol", protocol.to_owned()),
                KeyValue::new("status", status.to_owned()),
            ],
        );
    }

    pub fn record_auth_event(&self, event: &str, status: &str) {
        self.auth_events_atom.fetch_add(1, Ordering::Relaxed);
        self.auth_events_metric.add(
            1,
            &[
                KeyValue::new("event", event.to_owned()),
                KeyValue::new("status", status.to_owned()),
            ],
        );
    }

    pub fn record_k8s_request(&self, operation: &str, status: &str) {
        self.k8s_requests_atom.fetch_add(1, Ordering::Relaxed);
        self.k8s_requests_metric.add(
            1,
            &[
                KeyValue::new("operation", operation.to_owned()),
                KeyValue::new("status", status.to_owned()),
            ],
        );
    }

    pub fn record_ai_request(&self, provider: &str, status: &str) {
        self.ai_requests_atom.fetch_add(1, Ordering::Relaxed);
        self.ai_requests_metric.add(
            1,
            &[
                KeyValue::new("provider", provider.to_owned()),
                KeyValue::new("status", status.to_owned()),
            ],
        );
    }

    #[must_use]
    pub fn summary(&self) -> TelemetrySummary {
        TelemetrySummary {
            service_name: self.service_name.clone(),
            otlp_configured: self.otlp_configured,
            sessions_started_total: self.sessions_started_atom.load(Ordering::Relaxed),
            active_sessions: self.active_sessions_atom.load(Ordering::Relaxed),
            frames_encoded_total: self.frames_encoded_atom.load(Ordering::Relaxed),
            frames_dropped_total: self.frames_dropped_atom.load(Ordering::Relaxed),
            settings_updates_total: self.settings_updates_atom.load(Ordering::Relaxed),
            db_queries_total: self.db_queries_atom.load(Ordering::Relaxed),
            ssm_tunnels_total: self.ssm_tunnels_atom.load(Ordering::Relaxed),
            auth_events_total: self.auth_events_atom.load(Ordering::Relaxed),
            k8s_requests_total: self.k8s_requests_atom.load(Ordering::Relaxed),
            ai_requests_total: self.ai_requests_atom.load(Ordering::Relaxed),
            last_frame_encode_ms: self.last_encode_us.load(Ordering::Relaxed) as f64 / 1000.0,
            last_input_rtt_ms: self.last_rtt_us.load(Ordering::Relaxed) as f64 / 1000.0,
        }
    }

    /// Encode all collected OpenTelemetry metrics into Prometheus text exposition format.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let metric_families = self.prom_registry.gather();
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        if encoder.encode(&metric_families, &mut buffer).is_ok() {
            String::from_utf8_lossy(&buffer).into_owned()
        } else {
            String::new()
        }
    }

    /// Return the current tracing span's W3C trace ID (32-hex) when sampled/active,
    /// falling back to a unique 32-hex correlation ID.
    #[must_use]
    pub fn current_trace_id_hex() -> String {
        let span = tracing::Span::current();
        let ctx = span.context();
        let span_ref = ctx.span();
        let sc = span_ref.span_context();
        if sc.is_valid() {
            sc.trace_id().to_string()
        } else {
            "00000000000000000000000000000000".to_owned()
        }
    }

    /// Extract W3C `traceparent` parent context from HTTP headers into a `HashMap`.
    #[must_use]
    pub fn extract_context(headers: &HashMap<String, String>) -> opentelemetry::Context {
        global::get_text_map_propagator(|prop| prop.extract(headers))
    }
}

#[cfg(test)]
mod tests {
    use super::TelemetryHub;

    #[test]
    fn exports_prometheus_metrics_after_recording() {
        let hub = TelemetryHub::build("operquay-test", None, 1.0, false);
        hub.record_session_started("rdp", "auto_adaptive");
        hub.record_frame_encoded("oqr2_jpeg", 2.45);
        hub.record_input_rtt("rdp", 14.2);
        hub.record_settings_update("ultra_low_latency");
        hub.record_db_query("duckdb", "ok", 1.8);
        hub.record_ssm_tunnel("rdp", "started");
        hub.record_auth_event("login", "ok");
        hub.record_k8s_request("list", "ok");
        hub.record_ai_request("anthropic", "ok");

        let prom = hub.render_prometheus();
        assert!(prom.contains("operquay_sessions_started"));
        assert!(prom.contains("operquay_frames_encoded"));
        assert!(prom.contains("operquay_settings_updates"));
        assert!(prom.contains("operquay_db_queries"));
        assert!(prom.contains("operquay_db_query_duration_ms"));
        assert!(prom.contains("operquay_ssm_tunnels"));
        assert!(prom.contains("operquay_auth_events"));
        assert!(prom.contains("operquay_k8s_requests"));
        assert!(prom.contains("operquay_ai_requests"));

        let summary = hub.summary();
        assert_eq!(summary.sessions_started_total, 1);
        assert_eq!(summary.active_sessions, 1);
        assert_eq!(summary.frames_encoded_total, 1);
        assert_eq!(summary.settings_updates_total, 1);
        assert_eq!(summary.db_queries_total, 1);
        assert_eq!(summary.ssm_tunnels_total, 1);
        assert_eq!(summary.auth_events_total, 1);
        assert_eq!(summary.k8s_requests_total, 1);
        assert_eq!(summary.ai_requests_total, 1);

        hub.record_session_ended("rdp");
        assert_eq!(hub.summary().active_sessions, 0);
    }
}
