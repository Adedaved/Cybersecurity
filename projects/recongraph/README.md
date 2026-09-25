# ReconGraph

ReconGraph is a passive-first attack-surface inventory for a domain you are authorized to assess. It resolves explicitly supplied names, checks HTTP/S reachability, stores timestamped evidence in SQLite, and reports changes between observations.

## Architecture

`domain + candidate names -> scope check -> DNS -> HTTP/S metadata -> SQLite observations -> change report`

It does not brute-force subdomains or crawl third-party infrastructure. Every candidate must remain beneath the supplied root domain.

## Usage

```bash
python projects/recongraph/recongraph.py example.com --names www,api --output recon.db
python projects/recongraph/recongraph.py example.com --names www,api --output recon.db --json
```

## Sample output

```text
ReconGraph root=example.com run=1
example.com 93.184.216.34 https:200
www.example.com 93.184.216.34 https:200
```

## Limitations

- DNS and HTTP evidence is a point-in-time observation.
- Redirects are recorded but not followed, preventing accidental out-of-scope traversal.
- Technology fingerprinting is deliberately limited to reported headers.
