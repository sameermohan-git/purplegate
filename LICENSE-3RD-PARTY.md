# Third-party licenses — bundled tools

purplegate itself is MIT-licensed. The published Docker image bundles
unmodified third-party binaries; their upstream licenses apply to those
binaries. purplegate does not link against them — it invokes them as
separate processes.

| Tool | Version | License | Source |
|---|---|---|---|
| gitleaks | 8.30.1 | MIT | https://github.com/gitleaks/gitleaks |
| trufflehog | 3.95.2 | AGPL-3.0 | https://github.com/trufflesecurity/trufflehog |
| osv-scanner | 2.3.5 | Apache-2.0 | https://github.com/google/osv-scanner |
| syft | 1.43.0 | Apache-2.0 | https://github.com/anchore/syft |
| actionlint | 1.7.12 | MIT | https://github.com/rhysd/actionlint |
| semgrep | 1.161.0 | LGPL-2.1-or-later | https://github.com/semgrep/semgrep |
| checkov | 3.2.524 | Apache-2.0 | https://github.com/bridgecrewio/checkov |
| zizmor | 1.24.1 | MIT | https://github.com/zizmorcore/zizmor |
| pip-audit | 2.10.0 | Apache-2.0 | https://github.com/pypa/pip-audit |

## AGPL note (trufflehog)

Trufflehog is AGPL-3.0. That license imposes obligations on **modification
and network-service redistribution** of the software. purplegate:

- Invokes the unmodified `trufflehog` binary as a subprocess.
- Does not statically or dynamically link against trufflehog code.
- Does not host trufflehog as a network service.
- Preserves trufflehog's upstream copyright and license notices inside the
  bundled binary.

Consumers running purplegate as a GitHub Action inherit the same posture.
If you fork purplegate and **modify** its invocation of trufflehog (or bundle
a modified trufflehog), you may incur AGPL obligations that MIT does not
impose. If unsure, remove trufflehog from your fork or consult counsel.

Upstream versions are re-verified against each tool's GitHub release notes
on every Dockerfile bump — see the pinned `ARG <TOOL>_VERSION=...` lines.
