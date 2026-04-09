#!/bin/sh
set -eu

SRC_ROOT="${1:-/etc/breathgslb}"
DST_ROOT="${2:-demo/lightitup}"

tmp_config="$(mktemp)"
trap 'rm -f "$tmp_config"' EXIT INT TERM

# Keep the repo demo config in file-based layout even if the live config has
# ad hoc inline zones while testing.
awk '
  /^zones:[[:space:]]*$/ { exit }
  { print }
' "$SRC_ROOT/config.yaml" >"$tmp_config"

install -d "$DST_ROOT"
install -d "$DST_ROOT/zones"
install -d "$DST_ROOT/reverse"

rm -f "$DST_ROOT"/zones/*.fwd.yaml "$DST_ROOT"/reverse/*.fwd.yaml "$DST_ROOT"/reverse/*.rev.yaml

install -m 0644 "$tmp_config" "$DST_ROOT/config.yaml"

found=0
for f in "$SRC_ROOT"/zones/*.fwd.yaml; do
  [ -e "$f" ] || continue
  base="$(basename "$f")"
  case "$base" in
    *.in-addr.arpa.fwd.yaml|*.ip6.arpa.fwd.yaml)
      install -m 0644 "$f" "$DST_ROOT/reverse/${base%.fwd.yaml}.rev.yaml"
      ;;
    *)
      install -m 0644 "$f" "$DST_ROOT/zones/"
      ;;
  esac
  found=1
done
if [ "$found" -eq 0 ]; then
  echo "no zone files found under $SRC_ROOT/zones" >&2
fi

found=0
for f in "$SRC_ROOT"/reverse/*.fwd.yaml "$SRC_ROOT"/reverse/*.rev.yaml; do
  [ -e "$f" ] || continue
  base="$(basename "$f")"
  case "$base" in
    *.fwd.yaml)
      base="${base%.fwd.yaml}.rev.yaml"
      ;;
  esac
  install -m 0644 "$f" "$DST_ROOT/reverse/$base"
  found=1
done
if [ "$found" -eq 0 ]; then
  echo "no reverse files found under $SRC_ROOT/reverse" >&2
fi

echo "==> synced live demo data from $SRC_ROOT into $DST_ROOT"
