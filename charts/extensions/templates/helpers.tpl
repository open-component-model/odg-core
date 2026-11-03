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
