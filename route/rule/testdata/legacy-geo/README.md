# Synthetic legacy GeoIP fixtures

These small, real MaxMind databases use the `sing-geoip` string-record format.
They contain synthetic category labels, not real geographic claims:

| Prefix | geoip-a.db | geoip-b.db |
| --- | --- | --- |
| 1.1.1.0/24 | aa | bb |
| 8.8.8.0/24 | bb | aa |
| 2001:4860::/32 | aa | bb |
| 2606:4700::/32 | bb | aa |

Generated with the official `github.com/maxmind/mmdbwriter` v1.0.0:
`Options{BuildEpoch: 1, DatabaseType: "sing-geoip", Languages: []string{"aa", "bb"}, IPVersion: 6, RecordSize: 24}`.
Each prefix is inserted with `mmdbtype.String` and the file written with `Tree.WriteTo`.
The fixed timestamp makes regeneration deterministic. The writer is not a project dependency.
