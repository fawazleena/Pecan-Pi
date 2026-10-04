#!/bin/sh
# Benign traffic generator for the anomaly-detection baseline.
# Imitates the appliance's normal duty cycle: DNS lookups, a few HTTPS
# fetches to well-known sites, and an occasional apt update. Non-destructive.

SITES="google.com wikipedia.org github.com cloudflare.com microsoft.com
apple.com amazon.com youtube.com stackoverflow.com python.org kali.org
debian.org mozilla.org bbc.com reddit.com"
APT_STAMP=/var/tmp/pecan-trafficgen-apt

pick() { printf '%s\n' $SITES | shuf -n "$1"; }

for d in $(pick "$(shuf -i 5-8 -n 1)"); do
    getent hosts "$d" >/dev/null
done

for d in $(pick "$(shuf -i 3-5 -n 1)"); do
    curl -s -o /dev/null --max-time 10 "https://$d/"
    sleep "$(shuf -i 1-5 -n 1)"
done

# apt update at most every 6 hours
if [ ! -e "$APT_STAMP" ] || [ -n "$(find "$APT_STAMP" -mmin +360)" ]; then
    apt-get update -qq >/dev/null 2>&1 && touch "$APT_STAMP"
fi

exit 0  # best-effort: a failed fetch should not mark the unit failed
