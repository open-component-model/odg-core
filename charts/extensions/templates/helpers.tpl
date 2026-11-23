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
Renders the OTel env vars shared by all ODG workloads. `global.otlpEndpoint` is
always injected explicitly by the operator or service-provider-odg controller
(empty disables tracing, non-empty exports to that collector). Helm propagates
the global value to every extension sub-chart. Absent = empty = off.

Intended use inside each workload's env: block:

  {{- include "odg.otelEnv" . | nindent 12 }}

OTEL_SERVICE_NAME defaults to the sub-chart name. Workloads whose process name
differs from the chart name pass an override:

  {{- include "odg.otelEnv" (mergeOverwrite (deepCopy .) (dict "serviceName" "malware")) | nindent 12 }}

`odg.otelResourceAttrs` additionally injects k8s pod identity via the downward
API into OTEL_RESOURCE_ATTRIBUTES. Defined separately because it uses valueFrom
entries, which make it unusable inline with `- name: X` entries.

  {{- include "odg.otelResourceAttrs" (mergeOverwrite (deepCopy .) (dict "containerName" "freshclam")) | nindent 12 }}
*/}}
{{- define "odg.otelEnv" -}}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ .Values.global.otlpEndpoint | default "" | quote }}
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

k8s.container.name defaults to the chart name; workloads whose container
differs (freshclam, sla-report) pass an override like odg.otelEnv's serviceName:

  {{- include "odg.otelResourceAttrs" (mergeOverwrite (deepCopy .) (dict "containerName" "freshclam")) | nindent 12 }}
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
  value: k8s.pod.name=$(K8S_POD_NAME),k8s.pod.uid=$(K8S_POD_UID),k8s.namespace.name=$(K8S_POD_NAMESPACE),k8s.container.name={{ .containerName | default .Chart.Name }}
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
