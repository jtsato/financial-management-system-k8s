{{/*
Iterate over configmaps [from Values] and create an array of config map links
*/}}
{{- define "helpers.list-env-configmaps"}}
{{- $appNamePrefix  := .Values.application.name.prefix -}}
{{- range $key, $val := .Values.env.configmaps }}
- name: {{ $key }}
  valueFrom:
    configMapKeyRef:
      name: {{ $appNamePrefix }}-configmap
      key: {{ $key }}
{{- end}}
{{- end }}

{{/*
Iterate over secrets [from Values] and create an array of secret links
*/}}
{{- define "helpers.list-env-secrets"}}
{{- $appNamePrefix  := .Values.application.name.prefix -}}
{{- range $key, $val := .Values.env.secrets }}
- name: {{ $key }}
  valueFrom:
    secretKeyRef:
      name: {{ $appNamePrefix }}-secret
      key: {{ $key }}
{{- end}}
{{- end }}
