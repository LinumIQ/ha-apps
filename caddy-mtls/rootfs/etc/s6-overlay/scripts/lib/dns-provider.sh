#!/usr/bin/env bash
# ==============================================================================
# Home Assistant Add-on: Caddy mTLS Proxy
# ACME DNS-01 provider settings, shared by the init-caddy oneshot (renders and
# validates the Caddyfile) and the caddy service (runs Caddy).
#
# The secret never lands in the on-disk Caddyfile: the rendered `dns`
# directive only references environment variables through Caddy's {env.*}
# placeholders, which each provider module resolves when it is provisioned -
# in `caddy validate` (init-caddy) and in the running Caddy (initial load and
# every `caddy reload` by cert-mgr). Both processes must therefore export the
# variables themselves: an s6 oneshot's environment does not reach the
# long-running services.
#
# Syntax per module (UnmarshalCaddyfile at the pinned versions):
#   cloudflare v0.2.4      dns cloudflare <api_token>     (positional or block)
#   hetzner/v2 v2.0.1      dns hetzner <api_token>        (positional or block)
#   route53 v1.6.2         dns route53 { access_key_id <id>
#                                        secret_access_key <secret> }
#                          (a positional argument is rejected; the option
#                          value ACCESS_KEY_ID:SECRET_ACCESS_KEY is split at
#                          the first colon - AWS key IDs contain none)
# ==============================================================================

###############################################################################
# Export the environment variables the `dns` directive of a provider uses.
# Arguments:
#   $1 - provider (none|cloudflare|route53|hetzner)
#   $2 - the dns_api_token option value
# Returns 1 (exporting nothing) if the token does not fit the provider.
###############################################################################
dns_provider_export() {
    local provider="$1" token="$2"
    case "${provider}" in
        none)
            return 0
            ;;
        cloudflare|hetzner)
            [[ -n "${token}" ]] || return 1
            export DNS_API_TOKEN="${token}"
            ;;
        route53)
            local key_id="${token%%:*}" secret="${token#*:}"
            [[ "${token}" == *:* && -n "${key_id}" && -n "${secret}" ]] || return 1
            export DNS_AWS_ACCESS_KEY_ID="${key_id}"
            export DNS_AWS_SECRET_ACCESS_KEY="${secret}"
            ;;
        *)
            return 1
            ;;
    esac
}

###############################################################################
# Print the Caddyfile `dns` directive for a provider (placeholders only).
# Arguments:
#   $1 - provider (none|cloudflare|route53|hetzner)
#   $2 - indentation prefix (optional)
###############################################################################
dns_provider_directive() {
    local provider="$1" indent="${2:-}"
    case "${provider}" in
        cloudflare|hetzner)
            printf '%sdns %s {env.DNS_API_TOKEN}\n' "${indent}" "${provider}"
            ;;
        route53)
            printf '%sdns route53 {\n' "${indent}"
            printf '%s    access_key_id {env.DNS_AWS_ACCESS_KEY_ID}\n' "${indent}"
            printf '%s    secret_access_key {env.DNS_AWS_SECRET_ACCESS_KEY}\n' "${indent}"
            printf '%s}\n' "${indent}"
            ;;
    esac
}

###############################################################################
# Copy stdin to stdout with every DNS credential replaced by <redacted>: the
# raw option value (argument), and the exported variables.
# Arguments:
#   $1 - the dns_api_token option value (optional)
###############################################################################
dns_provider_redact() {
    local line secret
    local secrets=("${1:-}" "${DNS_API_TOKEN:-}" "${DNS_AWS_ACCESS_KEY_ID:-}" "${DNS_AWS_SECRET_ACCESS_KEY:-}")
    while IFS= read -r line || [[ -n "${line}" ]]; do
        for secret in "${secrets[@]}"; do
            [[ -n "${secret}" ]] && line="${line//"${secret}"/<redacted>}"
        done
        printf '%s\n' "${line}"
    done
}
