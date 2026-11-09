"""AIT Alert Data Set (AIT-ADS) loader: realistic, repetitive benign Wazuh volume with attack-phase labels.

The AIT-ADS (https://zenodo.org/records/8263181, CC BY 4.0; Landauer, Skopik and
Wurzenberger, CSET 2024) holds 2.29 million Wazuh alerts (Suricata's included)
from eight scenarios of the AIT-LDSv2 testbed: simulated users doing their work,
and a multi-step attack per scenario (scans, a webshell, password cracking, a
reverse shell, privilege escalation, DNS exfiltration). ``loader`` turns a
stratified, seeded sample of it into an ``lg-sotf eval`` dataset (``aitads_v1``);
``python -m tests.fixtures.aitads`` fetches the release and builds the sample.
Only the loader and a small fixture (``fixture/``, a few alerts of the release,
same licence) are in the repository; the release and the sample stay outside it.
"""
