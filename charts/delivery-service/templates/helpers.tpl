{{/* Keep in sync with the same-named defines in
charts/extensions/templates/helpers.tpl (this chart is standalone and cannot
include that helper). */}}
{{- define "odg.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 10000
runAsGroup: 10000
fsGroup: 10000
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "odg.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop:
    - ALL
{{- end -}}

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
