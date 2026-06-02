#!/bin/sh
# mxtr-proxy installer. One-shot.
#
#   curl -fsSL https://raw.githubusercontent.com/manfrommedan/mxtr-proxy/main/install.sh | sh -s 203.0.113.10
#
# Requires: docker + curl. Runs as root (writes /etc/mxtr-proxy/).
#
# Idempotent: re-running with the same host reuses the existing PSK (so
# previously distributed share-strings keep working). Pass --rotate to
# generate a new PSK.

set -eu

IMAGE="ghcr.io/manfrommedan/mxtr-proxy:latest"
ETC=/etc/mxtr-proxy
PORT=9290
NAME=mxtr-proxy

die() { echo "mxtr: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (writes /etc/mxtr-proxy/)"
command -v docker >/dev/null || die "docker not found"

ROTATE=0
HOST=""
for arg in "$@"; do
  case "$arg" in
    --rotate) ROTATE=1 ;;
    --help|-h)
      echo "Usage: $0 [--rotate] <public-ip>"
      echo "  <public-ip>    public IPv4/IPv6 literal clients connect to (no hostname; server validates it)"
      echo "  --rotate       force-regenerate PSK (invalidates existing clients)"
      exit 0 ;;
    -*) die "unknown flag: $arg" ;;
    *)  HOST="$arg" ;;
  esac
done

[ -n "$HOST" ] || die "missing <public-ip> argument. Try: $0 203.0.113.10"

mkdir -p "$ETC"
chmod 700 "$ETC"

echo "mxtr: pulling $IMAGE"
docker pull -q "$IMAGE" >/dev/null

if [ -f "$ETC/mxtr.env" ] && [ "$ROTATE" -eq 0 ]; then
  echo "mxtr: reusing existing PSK from $ETC/mxtr.env (use --rotate to regenerate)"
  . "$ETC/mxtr.env"
else
  echo "mxtr: generating new PSK"
  MXTR_PSK=$(docker run --rm "$IMAGE" -gen-psk | tr -d '\r\n')
  printf 'MXTR_PSK=%s\nMXTR_PUBLIC_IP=%s\n' "$MXTR_PSK" "$HOST" > "$ETC/mxtr.env"
  chmod 600 "$ETC/mxtr.env"
fi

echo "mxtr: stopping previous container (if any)"
docker rm -f "$NAME" 2>/dev/null || true

echo "mxtr: starting"
docker run -d \
  --name "$NAME" \
  --restart unless-stopped \
  --network host \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --log-driver json-file --log-opt max-size=1m --log-opt max-file=3 \
  -e MXTR_PSK="$MXTR_PSK" \
  "$IMAGE" \
  -tcp ":$PORT" -public-ip "$HOST" -log-level info >/dev/null

sleep 1
if ! docker ps --format '{{.Names}}' | grep -q "^${NAME}\$"; then
  echo "--- container died, logs: ---" >&2
  docker logs "$NAME" >&2 || true
  die "mxtr-proxy failed to start"
fi

SHARE=$(docker logs "$NAME" 2>&1 | grep -m1 'share-string:' | sed 's/.*share-string: //')

cat <<EOF

mxtr-proxy is up.

share-string:
  $SHARE

next:
  - paste the share-string into your Element X+ client
    (Settings -> Advanced -> АнтиЦензурный прокси)
  - open TCP :$PORT on your firewall: ufw allow $PORT/tcp
  - tail logs: docker logs -f $NAME
  - stop: docker rm -f $NAME
  - rotate PSK: $0 --rotate $HOST
EOF
