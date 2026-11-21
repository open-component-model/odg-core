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
taken from `otlpEndpoint` (set via the ODG CR's `otlp_endpoint`, empty
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
set empty otlpEndpoint must disable tracing — `default` and `empty`
treat "" as missing and would fall through to the derived URL. All content
inside the define renders into pod manifests, so no YAML comments in the body.
*/}}
{{- define "odg.otelEnv" -}}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ ternary (.Values.otlpEndpoint) (printf "http://telemetry-opentelemetry-collector.%s:4317" (.Values.target_namespace | default .Release.Namespace)) (hasKey .Values "otlpEndpoint") | quote }}
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

{{/*
Renders the tiered egress NetworkPolicy for a single extension workload. Replaces the
former blanket `egress: - {}` carve-outs (all destinations, all ports), which rendered
the shipped default-deny policy a no-op for egress.

Tiers, in order:

dns              UDP/TCP to the cluster DNS namespace (default kube-system,
                 override via global.netpol.dnsNamespaceLabels, e.g. OpenShift's
                 openshift-dns). Pod DNS resolution breaks without this. Ports
                 default to [53, 8053, 5353] — CNIs differ on pre-DNAT (Service
                 port 53) vs post-DNAT (pod port: Gardener CoreDNS serves on
                 8053, OpenShift dns-default on 5353) enforcement; override via
                 global.netpol.dnsPorts.
delivery-service TCP 8080+5000 to the delivery-service pods in the release
                 namespace (Service port pre-DNAT vs container port post-DNAT).
postgres         (optional, needs.postgres) TCP 5432 to the delivery DB. Matches
                 the in-cluster postgres pods by default (label pair
                 app.kubernetes.io/name=postgresql + component=primary is stable
                 across delivery-db deployments); out-of-cluster databases stay
                 reachable by adding CIDRs via global.netpol.postgresCidrs.
internet         (optional, needs.internet) TCP 443 to 0.0.0.0/0. Without L7/DNS-aware
                 egress filtering in the CNI this cannot be narrowed by hostname; the
                 port restriction still blocks non-443 exfil channels. Kubernetes API
                 server access rides this tier (endpoint IPs unknown at chart time), so
                 workloads using the Kubernetes API must keep needs.internet enabled.
otlp             TCP 4317+4318 (gRPC+HTTP) to the in-namespace OpenTelemetry collector.
                 Every workload emits the odg.otelEnv endpoint env vars; without this tier
                 tracing/metrics export to the same-namespace collector breaks under the
                 default-deny policy. Collector matched by pod labels (default
                 app.kubernetes.io/name=opentelemetry-collector, stable across installs
                 and independent of the helm release naming); override via
                 global.netpol.otlpCollectorLabels.
extra            raw egress rules appended verbatim from global.netpol.extraEgress
                 for targets the tiers cannot express (cross-namespace/external
                 collectors, egress proxies, non-443 registries, non-5432 DBs).

The policy lands in `namespaceOverride | default target_namespace | default
Release.Namespace` — matching the extension sub-charts (target_namespace) and
the odg-operator sub-chart (namespaceOverride) alike.

Intended use from an extension sub-chart template:

  {{- include "odg.netpol.egress" (list $podName . (dict "postgres" true)) }}

`needs` keys: postgres, internet — absence means false. `anywherePorts` adds extra TCP
ports to 0.0.0.0/0 (freshclam's plain-HTTP ClamAV CDN mirror). `targets` may carry raw
extra egress rules merged as additional tiers (delivery-db-backup's storage target):
`targets` is a list of full egress rule dicts rendered verbatim.
*/}}
{{/*
Renders the postgresql client label pair for workloads that talk to the delivery
database. Required once the database chart's network policy is tightened
(primary.networkPolicy.allowExternal: false): the upstream chart then only admits
pods labelled `<fullname>-client=true` in the database's own namespace. ODG pins
the database chart via fullnameOverride: delivery-db, hence the default
`delivery-db-client`; override global.netpol.dbClientLabelKey / dbClientLabelValue
in deployments whose database fullname differs.

Intended use inside the pod template's labels of DB-consuming workloads:

  labels:
    app: {{ $podName }}
    {{- include "odg.labels.dbClient" . | nindent 12 }}
*/}}
{{- define "odg.labels.dbClient" -}}
{{- $key := "delivery-db-client" -}}
{{- $val := "true" -}}
{{- with .Values.global.netpol -}}
{{- with .dbClientLabelKey -}}{{- $key = . -}}{{- end -}}
{{- with .dbClientLabelValue -}}{{- $val = . -}}{{- end -}}
{{- end -}}
{{ $key }}: {{ $val | quote }}
{{- end -}}

{{- define "odg.netpol.egress" -}}
{{- $podName := index . 0 -}}
{{- $ctx := index . 1 -}}
{{- $needs := index . 2 | default dict -}}
{{- $ns := $ctx.Values.namespaceOverride | default $ctx.Values.target_namespace | default $ctx.Release.Namespace -}}
{{- $dnsLabels := dict "kubernetes.io/metadata.name" "kube-system" -}}
{{- $dnsPorts := list 53 8053 5353 -}}
{{- $dnsNodeLocalIps := list "169.254.20.10" -}}
{{- $postgresCidrs := list -}}
{{- $otlpLabels := dict "app.kubernetes.io/name" "opentelemetry-collector" -}}
{{- $extraEgress := list -}}
{{- with ($ctx.Values.global).netpol -}}
{{- with .dnsNamespaceLabels -}}{{- $dnsLabels = . -}}{{- end -}}
{{- with .dnsPorts -}}{{- $dnsPorts = . -}}{{- end -}}
{{- if hasKey . "dnsNodeLocalIps" -}}{{- $dnsNodeLocalIps = .dnsNodeLocalIps -}}{{- end -}}
{{- with .postgresCidrs -}}{{- $postgresCidrs = . -}}{{- end -}}
{{- with .otlpCollectorLabels -}}{{- $otlpLabels = . -}}{{- end -}}
{{- with .extraEgress -}}{{- $extraEgress = . -}}{{- end -}}
{{- end -}}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-from-{{ $podName }}
  namespace: {{ $ns }}
spec:
  podSelector:
    matchLabels:
      app: {{ $podName }}
  policyTypes:
    - Egress
  egress:
    # cluster DNS — pod name resolution breaks without this; ports default to
    # [53, 8053, 5353] (Service port 53 pre-DNAT vs pod port post-DNAT:
    # Gardener CoreDNS serves on 8053, OpenShift dns-default on 5353)
    - to:
        - namespaceSelector:
            matchLabels:
              {{- toYaml $dnsLabels | nindent 14 }}
        {{- range $ip := $dnsNodeLocalIps }}
        # NodeLocal DNSCache: pods query the link-local IP on the node (default
        # 169.254.20.10), which namespace selectors can never match — set
        # global.netpol.dnsNodeLocalIps: [] on clusters without NodeLocal DNS
        - ipBlock:
            cidr: {{ $ip }}/32
        {{- end }}
      ports:
        {{- range $port := $dnsPorts }}
        - port: {{ $port }}
          protocol: UDP
        - port: {{ $port }}
          protocol: TCP
        {{- end }}
    # delivery-service API (in release namespace): destination is the
    # Service ClusterIP:8080 pre-DNAT but the pod IP:5000 post-DNAT; CNIs
    # differ on which side they enforce egress policy, so allow both ports
    - to:
        - podSelector:
            matchLabels:
              app: delivery-service
      ports:
        - port: 8080
          protocol: TCP
        - port: 5000
          protocol: TCP
    # OpenTelemetry collector in the release namespace (gRPC 4317 + HTTP 4318):
    # every workload carries the odg.otelEnv endpoint env vars; if no collector
    # matches the selector this tier is inert
    - to:
        - podSelector:
            matchLabels:
              {{- toYaml $otlpLabels | nindent 14 }}
      ports:
        - port: 4317
          protocol: TCP
        - port: 4318
          protocol: TCP
    # Kubernetes API server access post-DNAT: the translated endpoint IP:6443.
    # The pre-DNAT path (kubernetes.default ClusterIP:443) is covered by the
    # internet tier, so workloads using the Kubernetes API must keep
    # needs.internet enabled
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - port: 6443
          protocol: TCP
    {{- if $needs.postgres }}
    # delivery-database: in-cluster postgres pods by default (label pair is
    # stable across environments); external database hosts via
    # global.netpol.postgresCidrs
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: postgresql
              app.kubernetes.io/component: primary
        {{- range $cidr := $postgresCidrs }}
        - ipBlock:
            cidr: {{ $cidr | quote }}
        {{- end }}
      ports:
        - port: 5432
          protocol: TCP
    {{- end }}
    {{- if $needs.internet }}
    # HTTPS to arbitrary external endpoints (registries, APIs, CDNs)
    # cannot be narrowed by hostname without L7/DNS-aware egress filtering
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - port: 443
          protocol: TCP
    {{- end }}
    {{- range $port := $needs.anywherePorts }}
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - port: {{ $port }}
          protocol: TCP
    {{- end }}
    {{- if $needs.targets }}
    {{- toYaml $needs.targets | nindent 4 }}
    {{- end }}
    {{- if $extraEgress }}
    # verbatim extra egress rules from global.netpol.extraEgress
    {{- toYaml $extraEgress | nindent 4 }}
    {{- end }}
{{- end -}}
