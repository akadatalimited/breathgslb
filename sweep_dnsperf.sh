#!/usr/bin/env bash
set -euo pipefail
SERVER="${1:-2a02:8012:bc57:1::2}"
DATAFILE="${2:-queries-existing.txt}"
DUR="${3:-30}"
RATES=("5000" "10000" "20000" "30000" "40000" "50000" "70000" "90000")

echo "server,qps_target,qps_achieved,resp_received,resp_lost,avg_ms,p95_ms" > results.csv

for q in "${RATES[@]}"; do
  echo "==> Running ${q} qps"
  # dnsperf prints a summary; we parse a few lines
  OUT=$(dnsperf -s "$SERVER" -d "$DATAFILE" -l "$DUR" -Q "$q" 2>/dev/null)
  # Pull numbers (dnsperf output is pretty stable)
  ACH=$(echo "$OUT" | awk '/Queries per second:/{print $4}')
  RCVD=$(echo "$OUT" | awk '/Responses received:/{print $3}')
  LOST=$(echo "$OUT" | awk '/Response loss:/{print $3}' | tr -d '()%')
  AVG=$(echo "$OUT" | awk '/Average:/ {print $2}')
  P95=$(echo "$OUT" | awk '/95th percentile:/ {print $3}')
  echo "$SERVER,$q,$ACH,$RCVD,$LOST,$AVG,$P95" >> results.csv
done

echo "Done. See results.csv"
