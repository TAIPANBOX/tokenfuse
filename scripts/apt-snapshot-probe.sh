#!/usr/bin/env bash
# Run before any `apt-get ... --snapshot "$APT_SNAPSHOT"` line in CI.
#
# Two things, both about failing in a minute instead of an hour, and neither
# touches the pin itself (scripts/pinned-installs.sh still requires --snapshot):
#
#   1. Ask snapshot.ubuntu.com for the pinned snapshot's InRelease with a
#      bounded wait. On 2026-09-08 the service returned 502/503 on every dated
#      snapshot for hours; `apt-get update` treated the failed index fetches as
#      warnings, `install` then said "Unable to locate package clang", and a
#      re-run sat on `System deps` for 57 minutes against an outage that no
#      change in this repository caused or could fix. This turns that into one
#      `::error` line at the top of the log.
#
#   2. Give apt bounded timeouts and a single retry, and make a failed index
#      fetch an error rather than a warning (APT::Update::Error-Mode=any), so
#      that if the service dies between the probe and the install the step
#      still ends and says why. These bounds are per fetch, and apt fetches
#      dozens of index files: on 2026-09-08 a flapping service (InRelease
#      answered, later indexes 503ed) turned Retries=3 x 20 s x dozens of files
#      into 27 minutes. The probe catches "down", not "flapping"; the hard
#      bound for flapping is `timeout-minutes` on the workflow step itself,
#      which every snapshot-pinned step carries.
set -euo pipefail

snap="${APT_SNAPSHOT:?APT_SNAPSHOT is not set; the pin lives in the workflow env}"
# The base is overridable so gates-have-teeth.sh can point this at a closed
# port and at a one-shot local server, offline, and still exercise both ends.
base="${APT_SNAPSHOT_BASE:-https://snapshot.ubuntu.com}"
url="${base}/ubuntu/${snap}/dists/noble/InRelease"

# curl prints 000 itself when it never got a response; `|| true` only keeps
# set -e from ending the script before the message below is printed.
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 --retry 2 --retry-delay 5 "$url" 2>/dev/null || true)
code="${code:-000}"
if [ "$code" != "200" ]; then
	echo "::error::${base} is not serving snapshot ${snap} (HTTP ${code} for ${url}). This job pins apt to that snapshot and cannot proceed until the service is back; nothing in this repository changed."
	exit 1
fi

# Only where apt lives. On a developer Mac, where gates-have-teeth.sh also
# runs this, there is no apt.conf.d and nothing to bound.
if [ -d /etc/apt/apt.conf.d ]; then
	conf='Acquire::Retries "1";
Acquire::http::Timeout "20";
Acquire::https::Timeout "20";
APT::Update::Error-Mode "any";'
	if [ "$(id -u)" = 0 ]; then
		printf '%s\n' "$conf" >/etc/apt/apt.conf.d/99-ci-bounded
	else
		printf '%s\n' "$conf" | sudo tee /etc/apt/apt.conf.d/99-ci-bounded >/dev/null
	fi
	echo "snapshot ${snap} is served (HTTP 200); apt timeouts bounded"
else
	echo "snapshot ${snap} is served (HTTP 200); no apt here, nothing to bound"
fi
