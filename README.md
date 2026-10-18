# netcheck

Small Linux CLI that checks DNS, TCP, TLS and HTTP health for a list of domains.

## What it checks
| Layer | Result recorded |
|---|---|
| DNS | resolution time, addresses (TTL and CNAME if `dnspython` is installed) |
| TCP | connect time |
| TLS | protocol version, cipher, certificate expiry and days left |
| HTTP | status code and response time |

Output is one JSON line per domain; exit code is 1 if anything fails, so it
works in cron, systemd timers or CI.

Note: with `--insecure`, certificate expiry cannot be read, so the expiry check only runs with verification on (the default).

## Usage
```bash
python3 netcheck.py example.com github.com:443
python3 netcheck.py -f domains.txt --warn-days 21 --workers 20
python3 netcheck.py -f domains.txt | jq 'select(.ok==false)'
```

## Run on a schedule (cron)
```cron
*/15 * * * * /usr/bin/python3 /opt/netcheck/netcheck.py -f /opt/netcheck/domains.txt >> /var/log/netcheck.jsonl 2>> /var/log/netcheck.err
```

## systemd timer (alternative)
`/etc/systemd/system/netcheck.service`
```ini
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/netcheck/netcheck.py -f /opt/netcheck/domains.txt
```
`/etc/systemd/system/netcheck.timer`
```ini
[Timer]
OnCalendar=*:0/15
Persistent=true
[Install]
WantedBy=timers.target
```
Enable with `systemctl enable --now netcheck.timer`.
