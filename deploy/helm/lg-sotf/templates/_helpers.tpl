{{/* vim: set filetype=mustache: */}}

{{- define "lg-sotf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "lg-sotf.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Name of a component resource: <fullname>-<component>. */}}
{{- define "lg-sotf.componentName" -}}
{{- printf "%s-%s" (include "lg-sotf.fullname" .root | trunc 50 | trimSuffix "-") .component -}}
{{- end -}}

{{- define "lg-sotf.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "lg-sotf.labels" -}}
helm.sh/chart: {{ include "lg-sotf.chart" . }}
app.kubernetes.io/name: {{ include "lg-sotf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: lg-sotf
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Labels for a component: (dict "root" $ "component" "api") */}}
{{- define "lg-sotf.componentLabels" -}}
{{ include "lg-sotf.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "lg-sotf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lg-sotf.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "lg-sotf.annotations" -}}
{{- with .Values.commonAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "lg-sotf.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "lg-sotf.frontendImage" -}}
{{- $img := .Values.frontend.image -}}
{{- $tag := default .Chart.AppVersion $img.tag -}}
{{- if $img.digest -}}
{{- printf "%s@%s" $img.repository $img.digest -}}
{{- else -}}
{{- printf "%s:%s" $img.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "lg-sotf.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "lg-sotf.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "lg-sotf.runtimeSecretName" -}}
{{- default (include "lg-sotf.fullname" .) .Values.secrets.existingSecret -}}
{{- end -}}

{{- define "lg-sotf.configMapName" -}}
{{- printf "%s-config" (include "lg-sotf.fullname" .) -}}
{{- end -}}

{{/* Rendered settings file; also hashed into pod annotations to roll pods on change. */}}
{{- define "lg-sotf.settingsYaml" -}}
{{ toYaml .Values.settings }}
{{- end -}}

{{/* Container-level env shared by every lg-sotf process. */}}
{{- define "lg-sotf.env" -}}
- name: LG_SOTF_CONFIG_FILE
  value: /etc/lg-sotf/settings.yaml
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* envFrom: (dict "root" $ "owner" bool "bootstrap" bool ["shadow" bool]) */}}
{{- define "lg-sotf.envFrom" -}}
- secretRef:
    name: {{ include "lg-sotf.runtimeSecretName" .root }}
{{- if and .owner .root.Values.secrets.ownerSecret }}
- secretRef:
    name: {{ .root.Values.secrets.ownerSecret }}
{{- end }}
{{- if and .bootstrap .root.Values.secrets.bootstrapSecret }}
- secretRef:
    name: {{ .root.Values.secrets.bootstrapSecret }}
{{- end }}
{{- if and .shadow .root.Values.secrets.shadowSecret }}
- secretRef:
    name: {{ .root.Values.secrets.shadowSecret }}
{{- end }}
{{- with .root.Values.extraEnvFrom }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "lg-sotf.volumeMounts" -}}
- name: tmp
  mountPath: /tmp
- name: config
  mountPath: /etc/lg-sotf
  readOnly: true
{{- with .Values.extraVolumeMounts }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Volumes: (dict "root" $ "configMap" name) */}}
{{- define "lg-sotf.volumes" -}}
- name: tmp
  emptyDir:
    sizeLimit: {{ .root.Values.tmpSizeLimit }}
- name: config
  configMap:
    name: {{ .configMap }}
{{- with .root.Values.extraVolumes }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Pod-level scheduling: (dict "root" $ "component" name "values" componentValues) */}}
{{- define "lg-sotf.scheduling" -}}
{{- $v := .values -}}
{{- $root := .root -}}
{{- with (default $root.Values.nodeSelector $v.nodeSelector) }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with (default $root.Values.tolerations $v.tolerations) }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with (default $root.Values.affinity $v.affinity) }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- if $v.topologySpreadConstraints }}
topologySpreadConstraints:
  {{- toYaml $v.topologySpreadConstraints | nindent 2 }}
{{- else if $root.Values.topologySpread.enabled }}
topologySpreadConstraints:
  - maxSkew: {{ $root.Values.topologySpread.maxSkew }}
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: {{ $root.Values.topologySpread.zone.whenUnsatisfiable }}
    labelSelector:
      matchLabels:
        {{- include "lg-sotf.selectorLabels" (dict "root" $root "component" .component) | nindent 8 }}
  - maxSkew: {{ $root.Values.topologySpread.maxSkew }}
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: {{ $root.Values.topologySpread.hostname.whenUnsatisfiable }}
    labelSelector:
      matchLabels:
        {{- include "lg-sotf.selectorLabels" (dict "root" $root "component" .component) | nindent 8 }}
{{- end }}
{{- with $root.Values.priorityClassName }}
priorityClassName: {{ . }}
{{- end }}
{{- end -}}

{{- define "lg-sotf.podAnnotations" -}}
checksum/config: {{ include "lg-sotf.settingsYaml" .root | sha256sum }}
{{- with .root.Values.podAnnotations }}
{{ toYaml . }}
{{- end }}
{{- with .values.podAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "lg-sotf.podLabels" -}}
{{ include "lg-sotf.selectorLabels" . }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/part-of: lg-sotf
{{- with .root.Values.podLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "lg-sotf.redisStream" -}}
{{- $prefix := default "lgsotf" (dig "redis" "key_prefix" "" .root.Values.settings) -}}
{{- printf "%s:q:alerts:%s" $prefix .stream -}}
{{- end -}}
