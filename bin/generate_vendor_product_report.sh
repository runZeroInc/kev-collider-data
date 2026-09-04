#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

JSON_DIR="$ROOT/json"
ALIASES="$ROOT/bin/product-aliases.json"
REPORT_DIR="$ROOT/reports"
REPORT="$REPORT_DIR/vendor-product-sorted-kevs.md"

mkdir -p "$REPORT_DIR"

GENERATED="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

{
  printf '# KEV Vulnerabilities by Vendor and Product\n\n'
  printf 'Generated: %s\n\n' "$GENERATED"
  printf 'One row per vendor/product pair, with product names normalized via `bin/product-aliases.json`. Sorted by KEV count (highest first), then by most recent date added.\n\n'

  jq -s -r --slurpfile aliases "$ALIASES" '
    def md: gsub("\\|"; "\\\\|");
    $aliases[0] as $alias
    | map({
        cveID: .cveID,
        vendor: (.kev.vendorProject // "Unknown"),
        product: (.kev.product // "Unknown"),
        dateAdded: (.kev.dateAdded // ""),
        ransomware: (.kev.ransomware // false)
      }
      | .product = ($alias[.vendor][.product | ascii_downcase] // .product))
    | group_by([.vendor, (.product | ascii_downcase)])
    | map(
        (sort_by([.dateAdded, .cveID]) | last) as $newest
        # Case-only variants collapse to the most common spelling.
        | (group_by(.product) | max_by([length, .[0].product]) | .[0].product) as $display
        | {
            vendor: .[0].vendor,
            product: $display,
            count: length,
            latest: $newest.dateAdded,
            ransomware: (map(select(.ransomware)) | length),
            cve: $newest.cveID
          }
      )
    | sort_by([
        -.count,
        (.latest | explode | map(-.)),
        .vendor,
        .product
      ])
    | ["| Vendor | Product | KEV Count | Latest Date Added | Ransomware KEVs | Most Recently Added CVE |",
       "| --- | --- | ---: | --- | ---: | --- |"]
      + map("| \(.vendor | md) | \(.product | md) | \(.count) | \(.latest) | \(.ransomware) | \(.cve) |")
    | .[]
  ' "$JSON_DIR"/*.json
} > "$REPORT"

echo "Wrote $REPORT"
