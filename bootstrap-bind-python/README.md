Python script to generate signal zones and (optionally) BIND configuration for signal zones.

```
named-checkconf -l | grep -E ' (primary|secondary|master|slave|mirror)$' | awk '{print $1}'|python3 main.py /var/cache/bind/
```
