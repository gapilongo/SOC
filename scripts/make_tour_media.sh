#!/usr/bin/env bash
# Turns the recorded tour (scripts/record_tour.mjs) into the README media:
#   docs/media/tour.mp4  H.264, 1280 px wide, for the full-quality video link
#   docs/media/tour.gif  880 px wide, 6 fps, plays inline on GitHub
#
#   scripts/make_tour_media.sh <dir containing tour.webm>
#
# Needs ffmpeg on PATH, or FFMPEG=/path/to/ffmpeg (for example the binary from
# `pip install imageio-ffmpeg`).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${1:?usage: make_tour_media.sh <dir containing tour.webm>}/tour.webm"
FF="${FFMPEG:-ffmpeg}"
OUT="$ROOT/docs/media"
mkdir -p "$OUT"
[ -f "$SRC" ] || { echo "no $SRC" >&2; exit 1; }

"$FF" -loglevel error -y -i "$SRC" \
  -vf "scale=1280:-2:flags=lanczos,format=yuv420p" \
  -c:v libx264 -preset slow -crf 26 -movflags +faststart -an "$OUT/tour.mp4"

PALETTE="$(mktemp --suffix=.png)"
trap 'rm -f "$PALETTE"' EXIT
FILTERS="fps=6,scale=880:-1:flags=lanczos"
"$FF" -loglevel error -y -i "$SRC" -vf "$FILTERS,palettegen=max_colors=96:stats_mode=diff" "$PALETTE"
"$FF" -loglevel error -y -i "$SRC" -i "$PALETTE" \
  -lavfi "$FILTERS [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" "$OUT/tour.gif"

ls -l "$OUT/tour.mp4" "$OUT/tour.gif"
