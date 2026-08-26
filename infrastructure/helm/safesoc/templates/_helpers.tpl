{{/*
SafeSOC Helm chart — shared naming/label helpers (SS-079)
*/}}

{{- define "safesoc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "safesoc.fullname" -}}
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

{{- define "safesoc.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "safesoc.labels" -}}
helm.sh/chart: {{ include "safesoc.chart" . }}
{{ include "safesoc.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "safesoc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "safesoc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "safesoc.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{/*
Common backend/worker/beat environment — one place so the three pods
that all run the same image stay in sync (mirrors how docker-compose.yml
repeats the same block for backend/worker/beat).
*/}}
{{- define "safesoc.commonEnv" -}}
- name: OPENSEARCH_HOST
  value: {{ if .Values.opensearch.enabled }}{{ printf "%s-opensearch" (include "safesoc.fullname" .) }}{{ else }}{{ required "opensearch.enabled is false — set extraEnv.OPENSEARCH_HOST" .Values.extraEnv.OPENSEARCH_HOST }}{{ end }}
- name: OPENSEARCH_PORT
  value: "9200"
- name: POSTGRES_HOST
  value: {{ if .Values.postgresql.enabled }}{{ printf "%s-postgresql" (include "safesoc.fullname" .) }}{{ else }}{{ required "postgresql.enabled is false — set extraEnv.POSTGRES_HOST" .Values.extraEnv.POSTGRES_HOST }}{{ end }}
- name: POSTGRES_PORT
  value: "5432"
- name: POSTGRES_DB
  value: {{ .Values.postgresql.auth.database | quote }}
- name: POSTGRES_USER
  value: {{ .Values.postgresql.auth.username | quote }}
- name: REDIS_HOST
  value: {{ if .Values.redis.enabled }}{{ printf "%s-redis" (include "safesoc.fullname" .) }}{{ else }}{{ required "redis.enabled is false — set extraEnv.REDIS_HOST" .Values.extraEnv.REDIS_HOST }}{{ end }}
- name: REDIS_PORT
  value: "6379"
- name: LLM_PROVIDER
  value: {{ .Values.llm.provider | quote }}
- name: OLLAMA_HOST
  value: {{ .Values.llm.ollamaHost | quote }}
- name: OLLAMA_PORT
  value: {{ .Values.llm.ollamaPort | quote }}
- name: OLLAMA_MODEL
  value: {{ .Values.llm.ollamaModel | quote }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "safesoc.secretName" . }}
      key: postgres-password
- name: JWT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "safesoc.secretName" . }}
      key: jwt-secret
- name: GROQ_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "safesoc.secretName" . }}
      key: groq-api-key
- name: VIRUSTOTAL_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "safesoc.secretName" . }}
      key: virustotal-api-key
- name: ABUSEIPDB_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "safesoc.secretName" . }}
      key: abuseipdb-api-key
- name: TELEGRAM_BOT_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "safesoc.secretName" . }}
      key: telegram-bot-token
- name: TELEGRAM_CHAT_ID
  valueFrom:
    secretKeyRef:
      name: {{ include "safesoc.secretName" . }}
      key: telegram-chat-id
{{- range $key, $value := .Values.extraEnv }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- end -}}

{{- define "safesoc.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "safesoc.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Generates a random JWT secret on first install, but REUSES the value
already in the cluster on `helm upgrade` (via `lookup`) rather than
rotating it on every upgrade — a fresh secret every upgrade would
invalidate every issued JWT each time this chart is upgraded, which
would be a serious usability/production bug for a "production-
oriented" chart. `lookup` returns nothing during `helm template`/
`helm lint` (no live cluster), so a local render always shows a fresh
value — expected, documented Helm behavior, not a bug in this chart.
*/}}
{{- define "safesoc.jwtSecret" -}}
{{- if .Values.secrets.jwtSecret -}}
{{- .Values.secrets.jwtSecret -}}
{{- else -}}
{{- $existing := (lookup "v1" "Secret" .Release.Namespace (include "safesoc.secretName" .)) -}}
{{- if $existing -}}
{{- index $existing.data "jwt-secret" | b64dec -}}
{{- else -}}
{{- randAlphaNum 64 -}}
{{- end -}}
{{- end -}}
{{- end -}}
