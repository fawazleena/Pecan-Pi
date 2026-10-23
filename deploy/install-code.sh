#!/bin/sh
# Install the code that root-run services execute as root-owned copies in /opt/pecan (like
# pecan-helper in /usr/local/sbin). Never symlinks or bind mounts from /home/raven: anything the
# normal user (or a compromised panel running as that user) can edit must not run as root.
# Run after every change to one of these files, then restart the affected service:
#   sudo sh deploy/install-code.sh && sudo systemctl restart pecan-pipeline pecan-honeypot
set -eu
cd "$(dirname "$0")/.."
install -d -o root -g root -m 0755 /opt/pecan
install -o root -g root -m 0644 pipeline.py triage.py netinfo.py anomaly.py honeypot.py tailscale_derp.json /opt/pecan/
install -o root -g root -m 0755 trafficgen.sh /opt/pecan/
install -o root -g root -m 0755 pecan-helper.py /usr/local/sbin/pecan-helper
# The anomaly model is a pickle (loading it runs code), so the root pipeline only loads this copy.
# Not removed when the repo has none: retire it with  sudo rm /opt/pecan/anomaly_model.joblib
if [ -f anomaly_model.joblib ]; then
    install -o root -g root -m 0644 anomaly_model.joblib /opt/pecan/
    # Its label (anomaly.py label); without one the panel shows the old label as not matching.
    if [ -f anomaly_model.meta.json ]; then
        install -o root -g root -m 0644 anomaly_model.meta.json /opt/pecan/
    fi
fi
echo "installed into /opt/pecan:"; ls -l /opt/pecan
