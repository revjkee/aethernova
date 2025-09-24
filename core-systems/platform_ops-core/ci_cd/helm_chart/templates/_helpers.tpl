{{/*
Common helpers for llmops Helm chart templates
*/}}

{{- define "llmops.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "llmops.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- end }}

{{- define "llmops.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "llmops.labels" -}}
app.kubernetes.io/name: {{ include "llmops.name" . }}
helm.sh/chart: {{ include "llmops.chart" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "llmops.selectorLabels" -}}
app.kubernetes.io/name: {{ include "llmops.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
