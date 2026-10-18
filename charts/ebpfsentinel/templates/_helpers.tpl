{{/*
Chart name, truncated to 63 chars.
*/}}
{{- define "ebpfsentinel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name, truncated to 63 chars.
*/}}
{{- define "ebpfsentinel.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label value: name-version
*/}}
{{- define "ebpfsentinel.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "ebpfsentinel.labels" -}}
helm.sh/chart: {{ include "ebpfsentinel.chart" . }}
{{ include "ebpfsentinel.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels (immutable - used in matchLabels).
*/}}
{{- define "ebpfsentinel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ebpfsentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Common annotations applied to every resource.
*/}}
{{- define "ebpfsentinel.annotations" -}}
{{- with .Values.commonAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Container image with tag fallback to appVersion.
*/}}
{{- define "ebpfsentinel.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Warden broker image (the privileged sidecar).
*/}}
{{- define "ebpfsentinel.wardenImage" -}}
{{ .Values.wardenImage.repository }}:{{ .Values.wardenImage.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "ebpfsentinel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ebpfsentinel.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
The Pod Security Admission level this release claims, and what in these values
contradicts it. Returns one line per contradiction, empty when the pod satisfies
the claimed level. `privileged` admits everything, so it never contradicts.

The point is to fail at render time with the whole list rather than at apply
time with whatever the admission controller happened to notice first. Each line
names the value to change, because a PSA rejection names the field and not the
value that produced it.
*/}}
{{- define "ebpfsentinel.psaViolations" -}}
{{- $level := .Values.daemonset.podSecurityAdmission -}}
{{- if not (has $level (list "privileged" "baseline" "restricted")) -}}
{{- fail (printf "daemonset.podSecurityAdmission: %q is not a Pod Security Admission level (privileged, baseline, restricted)" $level) -}}
{{- end -}}
{{- if ne $level "privileged" -}}
{{- if .Values.daemonset.hostNetwork }}
- daemonset.hostNetwork=true shares the node's network namespace, which {{ $level }} forbids. The XDP and TC programs attach to the node's own interfaces, so turning it off limits the datapath to the pod's veth.
{{- end }}
{{- if .Values.daemonset.hostPID }}
- daemonset.hostPID=true shares the node's pid namespace, which {{ $level }} forbids. Cross-container DLP no longer needs it: the warden and the agent read the host procfs through the read-only /host/proc mount.
{{- end }}
{{- with .Values.daemonset.warden.securityContext.capabilities }}
{{- range .add }}
{{- if ne . "NET_BIND_SERVICE" }}
- daemonset.warden.securityContext.capabilities.add includes {{ . }}, which {{ $level }} forbids. The warden brokers bpffs delegation, netlink and the DLP uprobe with it.
{{- end }}
{{- end }}
{{- end }}
{{- with .Values.daemonset.securityContext.capabilities }}
{{- range .add }}
{{- if ne . "NET_BIND_SERVICE" }}
- daemonset.securityContext.capabilities.add includes {{ . }}, which {{ $level }} forbids.
{{- end }}
{{- end }}
{{- end }}
{{- if eq (.Values.daemonset.warden.securityContext.seccompProfile).type "Unconfined" }}
- daemonset.warden.securityContext.seccompProfile.type=Unconfined, which {{ $level }} forbids. The warden issues fsconfig, netlink and bpf.
{{- end }}
{{- if eq (.Values.daemonset.warden.securityContext.appArmorProfile).type "Unconfined" }}
- daemonset.warden.securityContext.appArmorProfile.type=Unconfined, which {{ $level }} forbids.
{{- end }}
{{- if eq (.Values.daemonset.securityContext.seccompProfile).type "Unconfined" }}
- daemonset.securityContext.seccompProfile.type=Unconfined, which {{ $level }} forbids. The agent unshares a user namespace and loads eBPF through its token.
{{- end }}
{{- if eq (.Values.daemonset.securityContext.appArmorProfile).type "Unconfined" }}
- daemonset.securityContext.appArmorProfile.type=Unconfined, which {{ $level }} forbids.
{{- end }}
- hostPath volumes are mounted (/sys/fs/bpf, /sys/kernel/debug, /sys/fs/cgroup, /proc, the state directory and /etc/machine-id), and {{ $level }} admits no hostPath volume. The programs, the pinned maps and the host procfs are all read through them.
{{- if .Values.daemonset.hostNetwork }}
- the agent declares ports {{ .Values.agent.httpPort }}, {{ .Values.agent.grpcPort }} and {{ .Values.agent.metricsPort }}, and with daemonset.hostNetwork=true those are host ports, which {{ $level }} forbids.
{{- end }}
{{- end -}}
{{- if eq $level "restricted" -}}
{{- if .Values.daemonset.securityContext.allowPrivilegeEscalation }}
- daemonset.securityContext.allowPrivilegeEscalation=true, which restricted forbids. The agent needs it to gain the capabilities it maps inside its own user namespace.
{{- end }}
{{- if eq (int .Values.daemonset.warden.securityContext.runAsUser) 0 }}
- daemonset.warden.securityContext.runAsUser=0, which restricted forbids.
{{- end }}
{{- end -}}
{{- end }}
