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

{{/*
============================================================================
Datastore credentials
============================================================================
The Bitnami postgresql/redis subcharts already own credential generation. When
`auth.password` is left unset they generate a random password into their own
Secret (<release>-postgresql key `password`, <release>-redis key `redis-password`),
and when `auth.existingSecret` is set they read that Secret instead. Nothing in
this chart should re-derive, re-generate, or interpolate that password.

The helpers below delegate to the subcharts' own name/key templates through
`.Subcharts.*`, so workloads mount exactly the Secret the subchart wrote. The
connection URL is then assembled at container start via Kubernetes `$(VAR)`
expansion rather than at render time, which is the only way to reference a
value the parent chart cannot see.

When a subchart is disabled the corresponding `external*` values must supply the
host and an existing Secret; the helpers `fail` with an actionable message
otherwise, rather than rendering a credential-less URL.
*/}}

{{- define "codehardener.postgresql.secretName" -}}
{{- if .Values.postgresql.enabled -}}
{{- include "postgresql.v1.secretName" .Subcharts.postgresql -}}
{{- else if .Values.externalDatabase.existingSecret -}}
{{- tpl .Values.externalDatabase.existingSecret . -}}
{{- else -}}
{{- fail "codehardener: postgresql.enabled=false but externalDatabase.existingSecret is empty. Set externalDatabase.host, externalDatabase.existingSecret and externalDatabase.existingSecretPasswordKey to point at a Secret holding the database password." -}}
{{- end -}}
{{- end }}

{{- define "codehardener.postgresql.passwordKey" -}}
{{- if .Values.postgresql.enabled -}}
{{- include "postgresql.v1.userPasswordKey" .Subcharts.postgresql -}}
{{- else -}}
{{- required "codehardener: externalDatabase.existingSecretPasswordKey must name the key inside externalDatabase.existingSecret that holds the database password." .Values.externalDatabase.existingSecretPasswordKey -}}
{{- end -}}
{{- end }}

{{- define "codehardener.postgresql.host" -}}
{{- if .Values.postgresql.enabled -}}
{{- include "postgresql.v1.primary.fullname" .Subcharts.postgresql -}}
{{- else -}}
{{- required "codehardener: postgresql.enabled=false, so externalDatabase.host must be set to the hostname of the external PostgreSQL server." .Values.externalDatabase.host -}}
{{- end -}}
{{- end }}

{{- define "codehardener.postgresql.port" -}}
{{- if .Values.postgresql.enabled -}}
{{- .Subcharts.postgresql.Values.primary.service.ports.postgresql -}}
{{- else -}}
{{- .Values.externalDatabase.port -}}
{{- end -}}
{{- end }}

{{- define "codehardener.postgresql.username" -}}
{{- if .Values.postgresql.enabled -}}
{{- .Values.postgresql.auth.username -}}
{{- else -}}
{{- .Values.externalDatabase.username -}}
{{- end -}}
{{- end }}

{{- define "codehardener.postgresql.database" -}}
{{- if .Values.postgresql.enabled -}}
{{- .Values.postgresql.auth.database -}}
{{- else -}}
{{- .Values.externalDatabase.database -}}
{{- end -}}
{{- end }}

{{/*
Redis auth is optional. Returns "true" when a password is in play.
*/}}
{{- define "codehardener.redis.authEnabled" -}}
{{- if .Values.redis.enabled -}}
{{- if .Values.redis.auth.enabled -}}true{{- end -}}
{{- else if .Values.externalRedis.existingSecret -}}true{{- end -}}
{{- end }}

{{- define "codehardener.redis.secretName" -}}
{{- if .Values.redis.enabled -}}
{{- include "redis.secretName" .Subcharts.redis -}}
{{- else if .Values.externalRedis.existingSecret -}}
{{- tpl .Values.externalRedis.existingSecret . -}}
{{- else -}}
{{- fail "codehardener: redis.enabled=false but externalRedis.existingSecret is empty. Set externalRedis.host, externalRedis.existingSecret and externalRedis.existingSecretPasswordKey, or set externalRedis.existingSecret to \"\" only if the external Redis genuinely has no password." -}}
{{- end -}}
{{- end }}

{{- define "codehardener.redis.passwordKey" -}}
{{- if .Values.redis.enabled -}}
{{- include "redis.secretPasswordKey" .Subcharts.redis -}}
{{- else -}}
{{- required "codehardener: externalRedis.existingSecretPasswordKey must name the key inside externalRedis.existingSecret that holds the Redis password." .Values.externalRedis.existingSecretPasswordKey -}}
{{- end -}}
{{- end }}

{{- define "codehardener.redis.host" -}}
{{- if .Values.redis.enabled -}}
{{- printf "%s-master" (include "common.names.fullname" .Subcharts.redis) -}}
{{- else -}}
{{- required "codehardener: redis.enabled=false, so externalRedis.host must be set to the hostname of the external Redis server." .Values.externalRedis.host -}}
{{- end -}}
{{- end }}

{{- define "codehardener.redis.port" -}}
{{- if .Values.redis.enabled -}}
{{- .Subcharts.redis.Values.master.service.ports.redis -}}
{{- else -}}
{{- .Values.externalRedis.port -}}
{{- end -}}
{{- end }}

{{/*
Env block giving a container DATABASE_URL and REDIS_URL.

CH_POSTGRES_PASSWORD / CH_REDIS_PASSWORD are declared first so that Kubernetes
can expand the `$(...)` references in the URLs that follow — env expansion only
resolves names defined earlier in the same container's env list.

Note: the password is substituted into a URL verbatim, so a password containing
URL-reserved characters (`@`, `:`, `/`, `?`, `#`) will not round-trip. The
subchart-generated defaults are alphanumeric and safe; operator-supplied
passwords should be too.
*/}}
{{- define "codehardener.datastoreEnv" -}}
- name: CH_POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "codehardener.postgresql.secretName" . }}
      key: {{ include "codehardener.postgresql.passwordKey" . }}
{{- if include "codehardener.redis.authEnabled" . }}
- name: CH_REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "codehardener.redis.secretName" . }}
      key: {{ include "codehardener.redis.passwordKey" . }}
{{- end }}
- name: DATABASE_URL
  value: "postgresql://{{ include "codehardener.postgresql.username" . }}:$(CH_POSTGRES_PASSWORD)@{{ include "codehardener.postgresql.host" . }}:{{ include "codehardener.postgresql.port" . }}/{{ include "codehardener.postgresql.database" . }}"
- name: REDIS_URL
{{- if include "codehardener.redis.authEnabled" . }}
  value: "redis://:$(CH_REDIS_PASSWORD)@{{ include "codehardener.redis.host" . }}:{{ include "codehardener.redis.port" . }}"
{{- else }}
  value: "redis://{{ include "codehardener.redis.host" . }}:{{ include "codehardener.redis.port" . }}"
{{- end }}
{{- end }}
