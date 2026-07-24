{{/*
Common labels
*/}}
{{- define "codehardener.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: codehardener
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{/*
Selector labels for a component
*/}}
{{- define "codehardener.selectorLabels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/instance: {{ .release }}
{{- end }}

{{/*
Full name with release
*/}}
{{- define "codehardener.fullname" -}}
{{ .Release.Name }}-codehardener
{{- end }}

{{/*
Backend fullname
*/}}
{{- define "codehardener.backend.fullname" -}}
{{ include "codehardener.fullname" . }}-backend
{{- end }}

{{/*
Scanner fullname
*/}}
{{- define "codehardener.scanner.fullname" -}}
{{ include "codehardener.fullname" . }}-scanner
{{- end }}

{{/*
Dashboard fullname
*/}}
{{- define "codehardener.dashboard.fullname" -}}
{{ include "codehardener.fullname" . }}-dashboard
{{- end }}
