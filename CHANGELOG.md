# Change Log

## v1.1.7
    * Converted to OpenSecOps supply-chain framework: hash-pinned dependencies (`boto3==1.42.94`, `urllib3>=2.7.0`, `pyyaml>=6.0,<7.0`), signed releases via Sigstore (SBOM + evidence tarball + SLSA Build L1 provenance, each accompanied by a Sigstore `.bundle`), daily CVE scan, OpenSSF Scorecard, customer-side release verification via `scripts/deploy.py` (Installer v3.0.11+). README H1 retitled from generic "README" to the component name. See `SECURITY.md`.

## v1.1.6
    * Enable auto-close workflow for external pull requests, enforcing the cathedral governance policy uniformly across all OpenSecOps repositories. Pull requests from non-team authors are closed automatically with a redirect comment pointing to the bug-report template, the GitHub Security Advisory flow, and the fork-under-MPL-2.0 path.

## v1.1.5
    * Updated GitHub remote references in publish.zsh script to use only OpenSecOps-Org, removed Delegat-AB

## v1.1.4
    * Updated GitHub organization name from CloudSecOps-Org to OpenSecOps-Org.
    * Updated references to CloudSecOps-Installer to Installer.

## v1.1.3
    * File paths corrected for the new name of the installer.

## v1.1.2
    * Updated LICENSE file to MPL 2.0.

## v1.1.1
    * Updated publish.zsh to support dual-remote publishing to CloudSecOps-Org repositories.

## v1.1.0
    * Added substitution logic for things like the Organization ID.

## v1.0.0
    * Initial release.
