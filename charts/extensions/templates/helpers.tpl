{{- define "image" -}}
{{- if $.ref -}}
{{ $.ref }}
{{- else -}}
{{- if hasPrefix "sha256:" (required "$.tag is required" $.tag) -}}
{{ required "$.repository is required" $.repository }}@{{ required "$.tag is required" $.tag }}
{{- else -}}
{{ required "$.repository is required" $.repository }}:{{ required "$.tag is required" $.tag }}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Renders a dedicated ServiceAccount + Role + RoleBinding for a single extension workload,
scoped to the workload's actual Kubernetes API usage. This replaces the shared catch-all
Role bound to the `default` service account (still kept in the delivery-service chart for
workloads that have not been migrated yet).

Intended use from an extension sub-chart template:

  {{- include "odg.rbac" . }}

The service account name matches the (sub-)chart name; reference it via
`serviceAccountName: {{ .Chart.Name }}` on the workload's pod spec.

Per-extension rules are declared in `charts/extensions/values.yaml` under
`<chart>.rbac.rules`. `update` is used wherever the code writes via
`replace_namespaced_*` (claim/unclaim backlog items, pushing log CRDs, scaling
deployments); `patch` is only granted where `patch_namespaced_*` is actually called
(artefact-enumerator priority bump).
*/}}
{{/*
Renders the OTel env vars shared by all ODG workloads. The endpoint is either
taken from global.otlpEndpoint (set via the ODG CR's `otlp_endpoint`, empty
disables tracing) or derived from the target namespace: the telemetry chart
ships the collector Service `telemetry-opentelemetry-collector` into the same
namespace (charts pinned via fullnameOverride), so pods resolve it via
namespace-local DNS.

The app code treats an empty OTEL_EXPORTER_OTLP_ENDPOINT as "tracing
off" (odg.telemetry.configure_telemetry no-ops), so this renders an empty
value with no further gating in every template.

Intended use inside each workload's env: block:

  {{- include "odg.otelEnv" . | nindent 12 }}

OTEL_SERVICE_NAME defaults to the sub-chart name and is the single service
identity for traces AND logs (configure_logging() falls back to it, so entry
points no longer hardcode service names). Workloads whose process name differs
from the chart name — charts shipping more than one process, e.g. clamav
(malware) + freshclam — pass an override:

  {{- include "odg.otelEnv" (mergeOverwrite (deepCopy .) (dict "serviceName" "malware")) | nindent 12 }}

`odg.otelResourceAttrs` additionally injects k8s metadata (pod name / uid /
namespace) via the downward API into OTEL_RESOURCE_ATTRIBUTES. Prefer it for
workloads whose traces must carry exact pod identity (server-side spans); the
collector's k8sattributes pod_association only resolves reliably for incoming
traffic, so client-side spans otherwise lack k8s.* resource attrs.

Intended use (or combine both into one include — see artefact-enumerator):

  {{- include "odg.otelEnv" . | nindent 12 }}
  {{- include "odg.otelResourceAttrs" . | nindent 12 }}

Implementation note: ternary+hasKey rather than `default` because an explicitly
set empty global.otlpEndpoint must disable tracing — `default` and `empty`
treat "" as missing and would fall through to the derived URL. All content
inside the define renders into pod manifests, so no YAML comments in the body.
*/}}
{{- define "odg.otelEnv" -}}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ ternary (.Values.global.otlpEndpoint) (printf "http://telemetry-opentelemetry-collector.%s:4317" (.Values.target_namespace | default .Release.Namespace)) (hasKey .Values.global "otlpEndpoint") | quote }}
- name: OTEL_SERVICE_NAME
  value: {{ .serviceName | default .Chart.Name | quote }}
- name: OTEL_SEMCONV_STABILITY_OPT_IN
  value: http
{{- end -}}

{{/*
k8s identity for OTel resource attributes via downward API. Complements the
collector-side k8sattributes enrichment: pod_association resolves only for
inbound traffic to the OTLP receiver (the Python SDK runs inside pods and
sends outbound, so pod IP -> pod lookup can miss for ClusterIP callers).

The SDK merges OTEL_RESOURCE_ATTRIBUTES into its resource on startup. Pair with
`odg.otelEnv` — defined separately because it includes fieldRef entries
(valueFrom), which make the include unusable inline with `- name: X` entries.
*/}}
{{- define "odg.otelResourceAttrs" -}}
- name: K8S_POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: K8S_POD_UID
  valueFrom:
    fieldRef:
      fieldPath: metadata.uid
- name: K8S_POD_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
- name: OTEL_RESOURCE_ATTRIBUTES
  value: k8s.pod.name=$(K8S_POD_NAME),k8s.pod.uid=$(K8S_POD_UID),k8s.namespace.name=$(K8S_POD_NAMESPACE),k8s.container.name={{ .Chart.Name }}
{{- end -}}

{{- define "odg.rbac" -}}
{{- $ns := .Values.target_namespace | default .Release.Namespace -}}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ $ns }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ $ns }}
rules:
  {{- toYaml (required (printf "%s.rbac.rules must be set" .Chart.Name) .Values.rbac.rules) | nindent 2 }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ $ns }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ .Chart.Name }}
subjects:
  - kind: ServiceAccount
    name: {{ .Chart.Name }}
    namespace: {{ $ns }}
{{- end -}}

{{/*
Renders only a ServiceAccount (no Role/RoleBinding) for workloads that never talk to the
Kubernetes API (e.g. freshclam). The token mount is always disabled. Takes a dict with
`name` (service account name) and the template `context` (`.`) for namespace resolution:

  {{- include "odg.serviceaccount" (dict "name" "freshclam" "context" .) }}
*/}}
{{- define "odg.serviceaccount" -}}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ .name }}
  namespace: {{ .context.Values.target_namespace | default .context.Release.Namespace }}
automountServiceAccountToken: false
{{- end -}}
