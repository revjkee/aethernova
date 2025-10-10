{{/*
Aethernova Chain Core — Helm helpers (industrial grade)
This file provides reusable helpers for names, labels, annotations, images,
security context, checksums and conditional features across templates.

Conventions:
- All names truncated to 63 chars and trimmed of trailing hyphens.
- All labels/annotations are stable and align with Kubernetes recommended labels.
- Avoids surprises by using `default`, `required`, `toYaml`, `tpl`, `nindent`.

Usage example (in templates):
metadata:
  name: {{ include "aethernova.fullname" . }}
  labels: {{ include "aethernova.labels" . | nindent 4 }}
*/}}

{{/* Chart name */}}
{{- define "aethernova.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Release fullname: <release>-<name> with 63 limit */}}
{{- define "aethernova.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "aethernova.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Chart version for labels (safe) */}}
{{- define "aethernova.chart" -}}
{{- printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_" ) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels (Kubernetes recommended app labels) */}}
{{- define "aethernova.labels" -}}
app.kubernetes.io/name: {{ include "aethernova.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | default .Chart.Version | quote }}
app.kubernetes.io/part-of: "aethernova-chain-core"
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
app.kubernetes.io/component: {{ .Values.component | default "node" | quote }}
helm.sh/chart: {{ include "aethernova.chart" . }}
{{- with .Values.labels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Selector labels (stable identity) */}}
{{- define "aethernova.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aethernova.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- with .Values.selectorLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Mergeable annotations for metadata */}}
{{- define "aethernova.annotations" -}}
{{- with .Values.annotations }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* ServiceAccount name (or default) */}}
{{- define "aethernova.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "aethernova.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Image reference builder (supports registry/repository/tag/digest) */}}
{{- define "aethernova.image" -}}
{{- $registry := .registry | default $.Values.image.registry -}}
{{- $repository := .repository | default $.Values.image.repository -}}
{{- $tag := .tag | default $.Values.image.tag -}}
{{- $digest := .digest | default $.Values.image.digest -}}
{{- if $digest -}}
{{- printf "%s/%s@%s" $registry $repository $digest -}}
{{- else -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- end -}}
{{- end -}}

{{/* Image pull secrets (list) */}}
{{- define "aethernova.imagePullSecrets" -}}
{{- if .Values.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.imagePullSecrets }}
  - name: {{ . | quote }}
{{- end }}
{{- end -}}
{{- end -}}

{{/* Pod security context defaults */}}
{{- define "aethernova.podSecurityContext" -}}
{{- $psc := .Values.podSecurityContext | default dict -}}
{{- if $psc }}
{{ toYaml $psc }}
{{- else }}
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
{{- end }}
{{- end -}}

{{/* Container security context defaults */}}
{{- define "aethernova.containerSecurityContext" -}}
{{- $csc := .Values.securityContext | default dict -}}
{{- if $csc }}
{{ toYaml $csc }}
{{- else }}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end }}
{{- end -}}

{{/* Standard probes (allow overrides) */}}
{{- define "aethernova.probes" -}}
{{- $p := .Values.probes | default dict -}}
{{- if $p.startupProbe }}
startupProbe:
{{ toYaml $p.startupProbe | nindent 2 }}
{{- end }}
{{- if $p.livenessProbe }}
livenessProbe:
{{ toYaml $p.livenessProbe | nindent 2 }}
{{- end }}
{{- if $p.readinessProbe }}
readinessProbe:
{{ toYaml $p.readinessProbe | nindent 2 }}
{{- end }}
{{- end -}}

{{/* Node scheduling helpers */}}
{{- define "aethernova.nodePlacement" -}}
{{- if .Values.nodeSelector }}
nodeSelector:
{{ toYaml .Values.nodeSelector | nindent 2 }}
{{- end }}
{{- if .Values.affinity }}
affinity:
{{ toYaml .Values.affinity | nindent 2 }}
{{- end }}
{{- if .Values.topologySpreadConstraints }}
topologySpreadConstraints:
{{ toYaml .Values.topologySpreadConstraints | nindent 2 }}
{{- end }}
{{- if .Values.tolerations }}
tolerations:
{{ toYaml .Values.tolerations | nindent 2 }}
{{- end }}
{{- end -}}

{{/* Compute checksum annotations for ConfigMap/Secret to force rolling updates */}}
{{- define "aethernova.checksumAnnotations" -}}
{{- $out := dict -}}
{{- range $i, $ref := . -}}
{{- $name := $ref.name -}}
{{- $kind := default "ConfigMap" $ref.kind -}}
{{- $ns := default $.Values.namespace (default $.Release.Namespace $ref.namespace) -}}
{{- if eq $kind "ConfigMap" -}}
{{- $cm := (lookup "v1" "ConfigMap" $ns $name) -}}
{{- if $cm -}}
{{- $_ := set $out (printf "checksum/configmap-%s" $name) ($cm.data | toYaml | sha256sum) -}}
{{- end -}}
{{- else if eq $kind "Secret" -}}
{{- $sec := (lookup "v1" "Secret" $ns $name) -}}
{{- if $sec -}}
{{- $_ := set $out (printf "checksum/secret-%s" $name) ($sec.data | toYaml | sha256sum) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{/* Ingress class name resolution */}}
{{- define "aethernova.ingressClassName" -}}
{{- default "nginx" .Values.ingress.className -}}
{{- end -}}

{{/* TLS secret name for ingress (optional) */}}
{{- define "aethernova.ingressTLSSecretName" -}}
{{- .Values.ingress.tls.secretName | default (printf "%s-tls" (include "aethernova.fullname" .)) -}}
{{- end -}}

{{/* Service names with suffixes (rpc, grpc, api, telemetry) */}}
{{- define "aethernova.svc.rpc" -}}
{{- printf "%s-rpc" (include "aethernova.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "aethernova.svc.grpc" -}}
{{- printf "%s-grpc" (include "aethernova.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "aethernova.svc.api" -}}
{{- printf "%s-api" (include "aethernova.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "aethernova.svc.telemetry" -}}
{{- printf "%s-telemetry" (include "aethernova.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* PVC name helper */}}
{{- define "aethernova.pvc" -}}
{{- $suffix := .suffix | default "data" -}}
{{- printf "%s-%s" (include "aethernova.fullname" .root) $suffix | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Render arbitrary dict using tpl with current context (common pattern) */}}
{{- define "aethernova.common.tplvalues.render" -}}
{{- $value := .value -}}
{{- $context := .context -}}
{{- if kindIs "string" $value -}}
{{- tpl $value $context -}}
{{- else -}}
{{- toYaml $value | tpl $context -}}
{{- end -}}
{{- end -}}

{{/* Feature flags: btc2_finality, parallel_exec, zk_priv_tx (informational) */}}
{{- define "aethernova.features" -}}
btc2_finality: {{ ternary "true" "false" (.Values.features.btc2_finality | default true) }}
parallel_exec: {{ ternary "true" "false" (.Values.features.parallel_exec | default true) }}
zk_priv_tx: {{ ternary "true" "false" (.Values.features.zk_priv_tx | default true) }}
{{- end -}}

{{/* Semver gating (example): require minimal Kubernetes version if set */}}
{{- define "aethernova.kubeVersionOK" -}}
{{- $min := .Values.kubeVersion.min | default "" -}}
{{- if $min -}}
{{- if not (semverCompare (printf ">= %s-0" $min) .Capabilities.KubeVersion.Version) -}}
{{- fail (printf "Kubernetes %s or later required, got: %s" $min .Capabilities.KubeVersion.Version) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Extra pod annotations merged with checksums */}}
{{- define "aethernova.podAnnotations" -}}
{{- $extra := .Values.podAnnotations | default dict -}}
{{- $checks := dict -}}
{{- if .Values.checksums }}
{{- $checks = include "aethernova.checksumAnnotations" .Values.checksums | fromYaml -}}
{{- end }}
{{- $merged := merge $checks $extra -}}
{{- toYaml $merged -}}
{{- end -}}

{{/* Standard ports (override-ready) */}}
{{- define "aethernova.ports" -}}
rpc: {{ .Values.ports.rpc | default 8545 }}
grpc: {{ .Values.ports.grpc | default 9090 }}
api: {{ .Values.ports.api | default 8080 }}
telemetry: {{ .Values.ports.telemetry | default 9100 }}
{{- end -}}

{{/* Resources (default sane limits; allow override) */}}
{{- define "aethernova.resources" -}}
{{- if .Values.resources }}
{{ toYaml .Values.resources }}
{{- else }}
limits:
  cpu: "2"
  memory: "2Gi"
requests:
  cpu: "500m"
  memory: "512Mi"
{{- end }}
{{- end -}}

{{/* Pull policy default */}}
{{- define "aethernova.imagePullPolicy" -}}
{{- .Values.image.pullPolicy | default "IfNotPresent" -}}
{{- end -}}

{{/* Determine if PodDisruptionBudget should be enabled */}}
{{- define "aethernova.pdb.enabled" -}}
{{- ternary "true" "false" (.Values.pdb.enabled | default true) -}}
{{- end -}}

{{/* Build a canonical DNS name for services (cluster-local) */}}
{{- define "aethernova.clusterDNS" -}}
{{- $svc := .svc -}}
{{- $ns  := .ns | default .Release.Namespace -}}
{{- printf "%s.%s.svc.cluster.local" $svc $ns -}}
{{- end -}}
