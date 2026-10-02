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
Renders ServiceAccount + Role + RoleBinding per workload. The ServiceAccount is always
rendered (pods reference it by name at admission time), but Role and RoleBinding are skipped
when the workload authenticates via an external kubeconfig instead of its ServiceAccount
token (`.Values.k8sCfgName` set -> env var K8S_CFG_NAME -> kubeconfig from a `kubernetes`
secret); in that mode the ServiceAccount mounts no token.
The ServiceAccount name matches the (sub-)chart name; set it as `serviceAccountName` on the
workload's pod spec.
*/}}

{{- define "odg.rbac.scan" -}}
apiVersion: v1
kind: ServiceAccount # always required: pods reference it by name at admission time
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Values.target_namespace | default .Release.Namespace }}
{{- if .Values.k8sCfgName }}
automountServiceAccountToken: false # external kubeconfig in use, no token needed
{{- end }}
{{- if empty .Values.k8sCfgName }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Values.target_namespace | default .Release.Namespace }}
rules:
  - apiGroups:
      - delivery-gear.gardener.cloud
    resources:
      - backlogitems
    verbs:
      - list
      - update # claim/unclaim backlog items via replace
  - apiGroups:
      - delivery-gear.gardener.cloud
    resources:
      - logcollections
    verbs:
      - create
      - get
      - update # replace
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Values.target_namespace | default .Release.Namespace }}
subjects:
  - kind: ServiceAccount
    name: {{ .Chart.Name }}
roleRef:
  kind: Role
  name: {{ .Chart.Name }}
  apiGroup: rbac.authorization.k8s.io
{{- end }}
{{- end -}}

{{- define "odg.rbac.logs" -}}
apiVersion: v1
kind: ServiceAccount # always required: pods reference it by name at admission time
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Values.target_namespace | default .Release.Namespace }}
{{- if .Values.k8sCfgName }}
automountServiceAccountToken: false # external kubeconfig in use, no token needed
{{- end }}
{{- if empty .Values.k8sCfgName }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Values.target_namespace | default .Release.Namespace }}
rules:
  - apiGroups:
      - delivery-gear.gardener.cloud
    resources:
      - logcollections
    verbs:
      - create
      - get
      - update # replace
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Values.target_namespace | default .Release.Namespace }}
subjects:
  - kind: ServiceAccount
    name: {{ .Chart.Name }}
roleRef:
  kind: Role
  name: {{ .Chart.Name }}
  apiGroup: rbac.authorization.k8s.io
{{- end }}
{{- end -}}

{{- define "odg.rbac.enumerator" -}}
apiVersion: v1
kind: ServiceAccount # always required: pods reference it by name at admission time
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Values.target_namespace | default .Release.Namespace }}
{{- if .Values.k8sCfgName }}
automountServiceAccountToken: false # external kubeconfig in use, no token needed
{{- end }}
{{- if empty .Values.k8sCfgName }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Values.target_namespace | default .Release.Namespace }}
rules:
  - apiGroups:
      - delivery-gear.gardener.cloud
    resources:
      - backlogitems
    verbs:
      - create
      - get
      - patch # retry on conflict
  - apiGroups:
      - delivery-gear.gardener.cloud
    resources:
      - logcollections
    verbs:
      - create
      - get
      - update # replace
  - apiGroups:
      - delivery-gear.gardener.cloud
    resources:
      - runtimeartefacts
    verbs:
      - list
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Values.target_namespace | default .Release.Namespace }}
subjects:
  - kind: ServiceAccount
    name: {{ .Chart.Name }}
roleRef:
  kind: Role
  name: {{ .Chart.Name }}
  apiGroup: rbac.authorization.k8s.io
{{- end }}
{{- end -}}

{{- define "odg.rbac.controller" -}}
apiVersion: v1
kind: ServiceAccount # always required: pods reference it by name at admission time
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Values.target_namespace | default .Release.Namespace }}
{{- if .Values.k8sCfgName }}
automountServiceAccountToken: false # external kubeconfig in use, no token needed
{{- end }}
{{- if empty .Values.k8sCfgName }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Values.target_namespace | default .Release.Namespace }}
rules:
  - apiGroups:
      - ""
    resources:
      - pods
    verbs:
      - list
  - apiGroups:
      - apps
    resources:
      - deployments
    verbs:
      - get
      - update # scale extensions via replace on deployments
  - apiGroups:
      - delivery-gear.gardener.cloud
    resources:
      - backlogitems
    verbs:
      - list
      - update # claim/unclaim via replace
      - watch
  - apiGroups:
      - delivery-gear.gardener.cloud
    resources:
      - logcollections
    verbs:
      - create
      - get
      - update # replace
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ .Chart.Name }}
  namespace: {{ .Values.target_namespace | default .Release.Namespace }}
subjects:
  - kind: ServiceAccount
    name: {{ .Chart.Name }}
roleRef:
  kind: Role
  name: {{ .Chart.Name }}
  apiGroup: rbac.authorization.k8s.io
{{- end }}
{{- end -}}
