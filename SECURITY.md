# Security policy

This repository is pre-alpha and does not yet claim to safely execute hostile cartridges. Please do not publish security reports containing working exploits in a public issue.

Report suspected vulnerabilities privately through GitHub's security advisory feature. Include the affected revision, operating system, reproduction steps, and the smallest cartridge or archive that demonstrates the issue.

The intended boundary is documented in `docs/architecture.md`. Missing permission prompts, archive validation bypasses, resource-limit bypasses, and host crashes caused by a cartridge are all considered security issues.
