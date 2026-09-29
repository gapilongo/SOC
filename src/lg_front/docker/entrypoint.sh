#!/bin/sh
# Generate the runtime configuration of the LG-SOTF web app, then exec nginx.
#
# Environment (all optional; empty means same-origin / disabled):
#   LG_SOTF_API_BASE_URL          origin of the API when it is not served from this host
#                                 (e.g. https://api.soc.example.com)
#   LG_SOTF_WS_URL                full WebSocket URL of /api/v1/ws (derived when empty)
#   LG_SOTF_API_UPSTREAM          proxy /api to this upstream (e.g. http://api:8000; scheme,
#                                 host and port only); for single-host setups without an ingress
#   LG_SOTF_OIDC_ISSUER, LG_SOTF_OIDC_CLIENT_ID     enable single sign-on (both required)
#   LG_SOTF_OIDC_SCOPE, LG_SOTF_OIDC_AUDIENCE, LG_SOTF_OIDC_TOKEN_TYPE (access_token|id_token),
#   LG_SOTF_OIDC_REDIRECT_URI, LG_SOTF_OIDC_AUTHORIZATION_ENDPOINT,
#   LG_SOTF_OIDC_TOKEN_ENDPOINT, LG_SOTF_OIDC_END_SESSION_ENDPOINT, LG_SOTF_OIDC_LABEL
#   LG_SOTF_CSP_CONNECT_SRC       extra origins for connect-src, space separated
#   LG_SOTF_HSTS_MAX_AGE          send Strict-Transport-Security with this max-age (seconds)
#   LG_SOTF_TRUSTED_PROXIES       space-separated addresses/CIDRs of a reverse proxy in front of
#                                 this container (e.g. the TLS terminator): its X-Forwarded-For
#                                 and X-Forwarded-Proto are honoured; anyone else's are ignored
#
# Values are validated before they are written into JavaScript or nginx
# configuration: a malformed value stops the container instead of producing
# an injectable config.
set -eu

# Output directory (nginx.conf includes /tmp/lg-sotf/*; overridable for tests).
OUT=${LG_SOTF_RUNTIME_DIR:-/tmp/lg-sotf}
TMP_ROOT=${LG_SOTF_NGINX_TMP:-/tmp/nginx}
mkdir -p "$OUT" "$TMP_ROOT/client_body" "$TMP_ROOT/proxy" "$TMP_ROOT/fastcgi" "$TMP_ROOT/uwsgi" "$TMP_ROOT/scgi"

fail() {
  echo "lg-sotf-frontend: $*" >&2
  exit 64
}

# URL: scheme://host[:port][/path], restricted character set, no credentials.
check_url() {
  name=$1 value=$2 schemes=$3
  [ -z "$value" ] && return 0
  printf '%s' "$value" | grep -Eq "^(${schemes})://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%/+-]*)?$" \
    || fail "$name must be a ${schemes} URL without credentials, query or unusual characters"
}

check_text() {
  name=$1 value=$2 pattern=$3
  [ -z "$value" ] && return 0
  printf '%s' "$value" | grep -Eq "^${pattern}$" || fail "$name contains characters that are not allowed"
}

origin_of() {
  printf '%s' "$1" | sed -E 's#^([a-z]+://[^/]+).*$#\1#'
}

API_BASE_URL=${LG_SOTF_API_BASE_URL:-}
WS_URL=${LG_SOTF_WS_URL:-}
API_UPSTREAM=${LG_SOTF_API_UPSTREAM:-}
OIDC_ISSUER=${LG_SOTF_OIDC_ISSUER:-}
OIDC_CLIENT_ID=${LG_SOTF_OIDC_CLIENT_ID:-}
OIDC_SCOPE=${LG_SOTF_OIDC_SCOPE:-}
OIDC_AUDIENCE=${LG_SOTF_OIDC_AUDIENCE:-}
OIDC_TOKEN_TYPE=${LG_SOTF_OIDC_TOKEN_TYPE:-}
OIDC_REDIRECT_URI=${LG_SOTF_OIDC_REDIRECT_URI:-}
OIDC_AUTHZ=${LG_SOTF_OIDC_AUTHORIZATION_ENDPOINT:-}
OIDC_TOKEN=${LG_SOTF_OIDC_TOKEN_ENDPOINT:-}
OIDC_END=${LG_SOTF_OIDC_END_SESSION_ENDPOINT:-}
OIDC_LABEL=${LG_SOTF_OIDC_LABEL:-}
CONNECT_EXTRA=${LG_SOTF_CSP_CONNECT_SRC:-}
HSTS=${LG_SOTF_HSTS_MAX_AGE:-}
TRUSTED_PROXIES=${LG_SOTF_TRUSTED_PROXIES:-}

check_url LG_SOTF_API_BASE_URL "$API_BASE_URL" 'https?'
check_url LG_SOTF_WS_URL "$WS_URL" 'wss?'
# The upstream is scheme://host[:port] only: a path would make nginx rewrite /api/... away.
API_UPSTREAM=${API_UPSTREAM%/}
if [ -n "$API_UPSTREAM" ]; then
  printf '%s' "$API_UPSTREAM" | grep -Eq '^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$' \
    || fail "LG_SOTF_API_UPSTREAM must be http(s)://host[:port] without a path"
fi
check_url LG_SOTF_OIDC_ISSUER "$OIDC_ISSUER" 'https?'
check_url LG_SOTF_OIDC_REDIRECT_URI "$OIDC_REDIRECT_URI" 'https?'
check_url LG_SOTF_OIDC_AUTHORIZATION_ENDPOINT "$OIDC_AUTHZ" 'https?'
check_url LG_SOTF_OIDC_TOKEN_ENDPOINT "$OIDC_TOKEN" 'https?'
check_url LG_SOTF_OIDC_END_SESSION_ENDPOINT "$OIDC_END" 'https?'
check_text LG_SOTF_OIDC_CLIENT_ID "$OIDC_CLIENT_ID" '[A-Za-z0-9._:@/-]{1,255}'
check_text LG_SOTF_OIDC_SCOPE "$OIDC_SCOPE" '[A-Za-z0-9 ._:/-]{1,512}'
check_text LG_SOTF_OIDC_AUDIENCE "$OIDC_AUDIENCE" '[A-Za-z0-9._:/-]{1,512}'
check_text LG_SOTF_OIDC_TOKEN_TYPE "$OIDC_TOKEN_TYPE" '(access_token|id_token)'
check_text LG_SOTF_OIDC_LABEL "$OIDC_LABEL" '[A-Za-z0-9 ._()-]{1,80}'
check_text LG_SOTF_HSTS_MAX_AGE "$HSTS" '[0-9]{1,9}'
for o in $CONNECT_EXTRA; do check_url LG_SOTF_CSP_CONNECT_SRC "$o" 'https?|wss?'; done
for p in $TRUSTED_PROXIES; do
  check_text LG_SOTF_TRUSTED_PROXIES "$p" '([0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?|[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(/[0-9]{1,3})?)'
done

# --- /config.js (values are validated above, so plain quoting is safe) -----------
oidc=null
if [ -n "$OIDC_ISSUER" ] && [ -n "$OIDC_CLIENT_ID" ]; then
  oidc="{\"issuer\":\"$OIDC_ISSUER\",\"clientId\":\"$OIDC_CLIENT_ID\",\"scope\":\"$OIDC_SCOPE\",\"audience\":\"$OIDC_AUDIENCE\",\"tokenType\":\"$OIDC_TOKEN_TYPE\",\"redirectUri\":\"$OIDC_REDIRECT_URI\",\"authorizationEndpoint\":\"$OIDC_AUTHZ\",\"tokenEndpoint\":\"$OIDC_TOKEN\",\"endSessionEndpoint\":\"$OIDC_END\",\"label\":\"$OIDC_LABEL\"}"
fi
cat > "$OUT/config.js.tmp" <<JS
// Generated at container start from environment variables. Public values only.
window.__LG_SOTF_CONFIG__ = Object.freeze({"apiBaseUrl":"$API_BASE_URL","wsUrl":"$WS_URL","oidc":$oidc});
JS
mv "$OUT/config.js.tmp" "$OUT/config.js"

# --- Content-Security-Policy ------------------------------------------------------
connect="'self'"
add_origin() {
  [ -z "$1" ] && return 0
  o=$(origin_of "$1")
  case " $connect " in *" $o "*) ;; *) connect="$connect $o" ;; esac
}
add_origin "$API_BASE_URL"
if [ -n "$API_BASE_URL" ] && [ -z "$WS_URL" ]; then
  add_origin "$(printf '%s' "$API_BASE_URL" | sed -e 's#^https://#wss://#' -e 's#^http://#ws://#')"
fi
add_origin "$WS_URL"
if [ -n "$OIDC_ISSUER" ]; then
  add_origin "$OIDC_ISSUER"
  add_origin "$OIDC_TOKEN"
fi
for o in $CONNECT_EXTRA; do add_origin "$o"; done

csp="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src $connect; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"

{
  echo "add_header Content-Security-Policy \"$csp\" always;"
  echo 'add_header X-Content-Type-Options "nosniff" always;'
  echo 'add_header X-Frame-Options "DENY" always;'
  echo 'add_header Referrer-Policy "no-referrer" always;'
  echo 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" always;'
  echo 'add_header Cross-Origin-Opener-Policy "same-origin" always;'
  echo 'add_header Cross-Origin-Resource-Policy "same-origin" always;'
  if [ -n "$HSTS" ]; then
    echo "add_header Strict-Transport-Security \"max-age=$HSTS; includeSubDomains\" always;"
  fi
} > "$OUT/headers.conf"

# --- IPv6 listener only where the kernel has IPv6 --------------------------------
if [ -f /proc/net/if_inet6 ]; then
  echo 'listen [::]:8080;' > "$OUT/listen-ipv6.conf"
else
  : > "$OUT/listen-ipv6.conf"
fi

# --- trusted reverse proxies (http context, always generated) ------------------------
# Only a listed proxy may set the client address (real_ip) and the original
# scheme; for everyone else X-Forwarded-Proto is this connection's $scheme.
{
  echo 'geo $realip_remote_addr $lg_trusted_proxy {'
  echo '  default 0;'
  for p in $TRUSTED_PROXIES; do echo "  $p 1;"; done
  echo '}'
  echo 'map "$lg_trusted_proxy:$http_x_forwarded_proto" $lg_forwarded_proto {'
  echo '  default $scheme;'
  echo '  "1:https" https;'
  echo '  "1:http" http;'
  echo '}'
} > "$OUT/proxy-http.conf"
{
  for p in $TRUSTED_PROXIES; do echo "set_real_ip_from $p;"; done
  if [ -n "$TRUSTED_PROXIES" ]; then
    echo 'real_ip_header X-Forwarded-For;'
    echo 'real_ip_recursive on;'
  fi
} > "$OUT/realip.conf"

# --- optional /api reverse proxy ----------------------------------------------------
if [ -n "$API_UPSTREAM" ]; then
  # The browser's WebSocket API cannot send headers, so the API takes the
  # access token in the /api/v1/ws query string. access_log never records
  # query strings (nginx.conf logs $uri), but error_log prints the whole
  # request line (e.g. "connect() failed" while the API restarts), so the
  # WebSocket location only logs critical errors.
  cat > "$OUT/api-proxy.conf" <<NGINX
location = /api/v1/ws {
  error_log /dev/stderr crit;
  proxy_pass $API_UPSTREAM;
  proxy_http_version 1.1;
  proxy_set_header Host \$host;
  proxy_set_header Upgrade \$http_upgrade;
  proxy_set_header Connection \$connection_upgrade;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto \$lg_forwarded_proto;
  proxy_set_header X-Forwarded-Host \$host;
  proxy_read_timeout 3600s;
  proxy_send_timeout 3600s;
  proxy_buffering off;
}
location /api/ {
  proxy_pass $API_UPSTREAM;
  proxy_http_version 1.1;
  proxy_set_header Host \$host;
  proxy_set_header Upgrade \$http_upgrade;
  proxy_set_header Connection \$connection_upgrade;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto \$lg_forwarded_proto;
  proxy_set_header X-Forwarded-Host \$host;
  proxy_read_timeout 3600s;
  proxy_send_timeout 3600s;
  proxy_buffering off;
  client_max_body_size 10m;
}
NGINX
else
  : > "$OUT/api-proxy.conf"
fi

echo "lg-sotf-frontend: config generated (api=${API_BASE_URL:-same-origin}, proxy=${API_UPSTREAM:-off}, oidc=$([ "$oidc" = null ] && echo off || echo on))" >&2
exec "$@"
