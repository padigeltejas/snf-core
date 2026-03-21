# Datasets

All datasets are loaded locally at startup. No internet access required.

## ja3/ja3_fingerprints.csv
Format: `ja3_hash,application,notes` | 50 entries
Maps JA3 MD5 hashes to application labels including malware families.

## ja4/ja4_fingerprints.csv
Format: `ja4_hash,application` | 110 entries
Same purpose as JA3 but uses the newer JA4 format.

## service-names-port-numbers.csv
IANA official port database | 6,255 entries | Public domain

## Runtime-Generated Files (not in repo)
- `rdns_cache.txt` — persistent reverse DNS cache
- `learned_doh.txt` — learned DoH provider IPs
- `learned_dot.txt` — learned DoT provider IPs

## Test PCAPs
- https://www.malware-traffic-analysis.net/
- https://mawi.wide.ad.jp/
- https://wiki.wireshark.org/SampleCaptures
