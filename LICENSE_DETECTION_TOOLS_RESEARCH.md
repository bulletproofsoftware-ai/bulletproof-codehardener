# License Detection Tools for AI-Generated Code: Research Summary

Research Date: February 21, 2026

## Executive Summary

Four leading open-source tools for snippet-level license detection in code:

| Tool | License | GitHub Stars | Last Release | Snippet Detection | Docker Support |
|------|---------|--------------|--------------|-------------------|-----------------|
| **SCANOSS** | GPL-2.0-or-later | ~100+ (SBOM WB: 59) | v1.30.0 | YES - native | YES - ghcr.io |
| **scancode-toolkit** | Apache-2.0 | 2.4k | Recent 2026 | YES - line-level | YES - Dockerfile |
| **licensee** | MIT | 864 | v9.18.0 (Nov 2025) | NO - file-level only | NO - Ruby gem |
| **ORT** | Apache-2.0 | 1.9k | Ongoing (milestones Feb 2026) | YES - via ScanOSS/FossID | YES - ghcr.io |

---

## Tool Deep Dives

### 1. SCANOSS (scanoss/scanner)

**Repository**: [GitHub - SCANOSS Organization](https://github.com/scanoss)

#### Licensing
- **SPDX License**: GPL-2.0-or-later (source code), open-data knowledgebase
- **Open Source**: Free and open-source SCA platform

#### GitHub Metrics
- **Stars**: Varies by component (SBOM Workbench: 59 stars, 11 forks)
- **GitHub Actions**: [SCANOSS Code Scan Action](https://github.com/marketplace/actions/scanoss-code-scan-action) available
- **Related Projects**:
  - scanner.java (deprecated)
  - scanner.php (PHP implementation)
  - scanner.py (Python CLI)

#### Snippet-Level Detection
**NATIVE SNIPPET MATCHING** - Core strength of SCANOSS
- [Advanced snippet matching with configurable scan tuning parameters](https://oss-compliance-tooling.org/Tooling-Landscape/OSS-Based-License-Compliance-Tools/) via `scanoss.json`
- Detects open source at **snippet, file, and component levels**
- Identifies both declared and undeclared open source components
- [FOSSLight Scanner has integrated SCANOSS for source code snippet matching](https://oss-compliance-tooling.org/Tooling-Landscape/OSS-Based-License-Compliance-Tools/)
- Demonstrates sophistication through configurable tuning for snippet detection needs

#### SBOM and Standards
- [Performs SBOM generation in SPDX and CycloneDX formats](https://www.scanoss.com/post/understanding-open-source-licence-compliance)
- Delivers transparency down to the code fragment level
- RESTful API based on OpenAPI standards

#### Docker & CI Integration
- **Docker Support**: YES
- **Container Scanning**: [Analyzes container images (Docker and OCI)](https://www.scanoss.com/post/introducing-container-scanning), generates complete SBOM
- **Python CLI**: Available for container and source scanning
- [GitHub Actions integration](https://github.com/marketplace/actions/scanoss-code-scan-action) with configurable policies

#### Special Capabilities
- Container image analysis with dependency discovery from base images
- License obligation tracking at snippet level
- Handles hundreds/thousands of additional components in containerized environments

#### Assessment for AI Code
- **IDEAL FOR**: Snippet-level detection of AI-generated code fragments
- **Strong points**: Native snippet matching, container support, open-data approach
- **Consideration**: GPL-2.0 license may require attention for some use cases

---

### 2. scancode-toolkit

**Repository**: [GitHub - aboutcode-org/scancode-toolkit](https://github.com/aboutcode-org/scancode-toolkit)

#### Licensing
- **SPDX License**: Apache-2.0 (primary)
- **Secondary Licenses**: CC-BY-4.0 (reference datasets), LGPL/MIT/BSD/GPL 2/3 (third-party components)
- **Open Source**: Completely free, no costs

#### GitHub Metrics
- **Stars**: 2.4k
- **Last Release**: Recent 2026 update with improved license detection rules
- **Releases**: [Full release history available](https://github.com/aboutcode-org/scancode-toolkit/releases)

#### Snippet-Level Detection
**YES - LINE-LEVEL GRANULARITY**
- [Detection results include start_line and end_line identifying where licenses/copyrights found](https://scancode-toolkit.readthedocs.io/en/stable/explanation/scancode-license-detection.html)
- License match data includes:
  - score, start_line, end_line, matched_length, match_coverage
  - matcher type, license_expression, rule_identifier
  - **All at snippet level granularity**

#### License Detection Mechanism
- [Uses full comparison (diff/red line) between database of license texts and code](https://scancode-toolkit.readthedocs.io/en/stable/explanation/scancode-license-detection.html)
- Does NOT rely solely on regex patterns or probabilistic matching
- Compiled search index for fast queries
- Grammar-based copyright detection with common/uncommon form support

#### SBOM and Standards
- [Output formats: JSON, YAML, HTML, CycloneDX, SPDX, Jinja templates](https://scancode-toolkit.readthedocs.io/en/latest/reference/license-detection-reference.html)
- [New license detection rules including EPL-2.0 and OpenJDK-related licensing](https://scancode-toolkit.readthedocs.io/en/latest/reference/license-detection-reference.html)
- Synchronized with latest SPDX license list

#### Docker & CI Integration
- **Docker Support**: YES - [Dockerfile included in repository](https://github.com/aboutcode-org/scancode-toolkit/blob/develop/Dockerfile)
- **Docker Hub Images**: [pgier/scancode-docker](https://hub.docker.com/r/pgier/scancode-docker), [beevelop/scancode](https://hub.docker.com/r/beevelop/scancode)
- **CI Integration**:
  - [ScanCode.io for advanced CI/CD pipelines](https://scancodeio.readthedocs.io/en/latest/quickstart.html)
  - GitHub Actions via scancode-action
  - Azure Pipelines support
  - Basic Docker command: `docker run -v /project:/project scancode [options]`
- **CI/CD Capabilities**: Automated scans on commits, PRs, releases, scheduled events

#### Python Package
- [Available on PyPI](https://pypi.org/project/scancode-toolkit/)
- Can be embedded directly in Python workflows

#### Assessment for AI Code
- **IDEAL FOR**: Comprehensive license and copyright detection with line-level precision
- **Strong points**: Mature tool (2.4k stars), Apache-2.0 licensed, excellent SPDX support
- **Perfect for**: Detailed compliance reports showing exact code locations

---

### 3. licensee (Ruby Gem)

**Repository**: [GitHub - licensee/licensee](https://github.com/licensee/licensee)

#### Licensing
- **SPDX License**: MIT
- **Open Source**: Used by GitHub officially

#### GitHub Metrics
- **Stars**: 864 stars, 312 forks
- **Last Release**: v9.18.0 (November 23, 2025)
  - Allows periods in file extensions for version numbers (e.g., LICENSE.Apache-2.0)
  - Prioritizes files more likely to contain standard licenses (COPYING before COPYRIGHT)

#### Snippet-Level Detection
**NO - FILE-LEVEL ONLY**
- Detects licenses at project/repository level
- Compares LICENSE files to known license database
- **NOT suitable for snippet-level AI code analysis**

#### License Detection Mechanism
- [Uses multiple "Matchers" strategies](https://github.com/licensee/licensee):
  - Exact match detection
  - Whitespace/copyright notice stripping for comparison
  - Sørensen–Dice coefficient for similarity (95% threshold)
- SPDX-compliant output
- Regular synchronization with ChooseALicense.com catalog

#### SBOM and Standards
- SPDX-compliant license keys and names
- Integrated with GitHub's license detection and chooser

#### Docker & CI Integration
- **Docker Support**: NO - Ruby gem only
- **CI Integration**: Limited to GitHub Actions (native tool)
- **Limitation**: CLI usage only, no containerization

#### Assessment for AI Code
- **NOT RECOMMENDED** for snippet-level detection
- **Use case**: Project-level license identification only
- **Limitation**: Cannot detect embedded/generated code fragments

---

### 4. OSS Review Toolkit (ORT)

**Repository**: [GitHub - oss-review-toolkit/ort](https://github.com/oss-review-toolkit/ort)

#### Licensing
- **SPDX License**: Apache-2.0
- **Open Source**: Linux Foundation project (part of ACT)

#### GitHub Metrics
- **Stars**: 1.9k
- **Last Releases**:
  - Ongoing milestones through February 2026
  - Analyzer Plugin milestone (Jan 20, 2026)
  - Generation improvements (Feb 7, 2026)
- **Community**: ORT Community Day scheduled April 9, 2025 (Ludwigsburg, Germany)

#### Snippet-Level Detection
**YES - VIA SPECIALIZED SCANNER INTEGRATION**
- [Specialized snippet detection feature: "snippet choice"](http://oss-review-toolkit.org/ort/docs/configuration/snippet-choice)
- [Integrates two third-party snippet scanners: ScanOSS and FossID](http://oss-review-toolkit.org/ort/docs/plugins/scanners/Licensee)
- Scanner component uses configured source code scanners abstracting scanner type
- Processes entire source code of packages and dependencies
- [Supports 20+ package managers](http://oss-review-toolkit.org/ort/docs/intro): Bazel, Cargo, Gradle, Maven, npm, PIP, pnpm, Yarn, etc.

#### Scanner Architecture
- **Analyzer**: Software Composition Analysis (SCA) for dependency identification
- **Scanner**: Detects license/copyright findings, abstracts scanner implementation
- **Reporter**: Generates CycloneDX and SPDX SBOM
- **Evaluator**: Applies policy automation

#### SBOM and Standards
- [CycloneDX and SPDX Software Bill of Materials generation](http://oss-review-toolkit.org/ort/docs/intro)
- [Built-in and configurable mapping of arbitrary licenses to SPDX IDs](http://oss-review-toolkit.org/ort/docs/configuration/license-classifications.md)
- [Comprehensive license handling configuration](http://oss-review-toolkit.org/ort/docs/guides/license-handling)

#### Docker & CI Integration
- **Docker Support**: YES - [Official Docker image: ghcr.io/oss-review-toolkit/ort](https://github.com/oss-review-toolkit/ort)
- **Usage**: `docker run --rm ghcr.io/oss-review-toolkit/ort [command]`
- **Volume Mounting**: `docker run -v /workspace:/project ort --info analyze`
- **GitLab CI**: [Dedicated ort-ci-gitlab integration](https://github.com/oss-review-toolkit/ort-ci-gitlab)
- **Jenkins**: [Jenkinsfile support with declarative pipelines](https://github.com/oss-review-toolkit/ort)
- **Performance**: Storage backends share scan results across pipeline runs and projects

#### Assessment for AI Code
- **IDEAL FOR**: Enterprise-scale license compliance with snippet detection via integrated scanners
- **Strong points**: Modular architecture, extensive CI/CD integration, policy automation
- **Consideration**: Requires configuration of external snippet scanners (ScanOSS/FossID)
- **Best for**: Complex multi-tool compliance orchestration

---

## Comparative Analysis

### Snippet Detection Capability Matrix

| Feature | SCANOSS | scancode-toolkit | licensee | ORT |
|---------|---------|-----------------|----------|-----|
| Native Snippet Detection | ✅ YES | ✅ YES (line-level) | ❌ NO | ✅ YES (via plugins) |
| Configurable Tuning | ✅ YES | ✅ YES | N/A | ✅ YES |
| File-level Granularity | ✅ YES | ✅ YES | ✅ YES | ✅ YES |
| Start/End Line Numbers | ✅ YES | ✅ YES | ❌ NO | ✅ YES |
| Match Confidence Score | ✅ YES | ✅ YES | ✅ YES | ✅ YES |

### Production Readiness & CI/CD

| Factor | SCANOSS | scancode-toolkit | licensee | ORT |
|--------|---------|-----------------|----------|-----|
| Docker Support | ✅ YES | ✅ YES | ❌ NO | ✅ YES |
| GitHub Actions | ✅ YES | ✅ YES | ✅ YES | ✅ YES (via templates) |
| GitLab CI | ✅ YES | ✅ YES | ❌ NO | ✅ YES (dedicated) |
| Jenkins Support | ✅ YES | ✅ YES | ❌ NO | ✅ YES |
| Container Scanning | ✅ YES | ⚠️ Limited | ❌ NO | ✅ YES |
| API/REST Support | ✅ YES | ⚠️ via ScanCode.io | ❌ NO | ✅ YES |

### License & Compliance

| Aspect | SCANOSS | scancode-toolkit | licensee | ORT |
|--------|---------|-----------------|----------|-----|
| License Type | GPL-2.0-or-later | Apache-2.0 | MIT | Apache-2.0 |
| SPDX Output | ✅ YES | ✅ YES | ✅ YES | ✅ YES |
| CycloneDX Output | ✅ YES | ✅ YES | ❌ NO | ✅ YES |
| Free/Open | ✅ YES | ✅ YES | ✅ YES | ✅ YES |

### Maturity & Community

| Metric | SCANOSS | scancode-toolkit | licensee | ORT |
|--------|---------|-----------------|----------|-----|
| GitHub Stars | ~100+ | 2.4k | 864 | 1.9k |
| Activity Level | Active | Very Active | Active | Very Active |
| Enterprise Use | ✅ YES | ✅ YES | ✅ YES (GitHub) | ✅ YES |
| LF Backing | ⚠️ (industry) | ✅ (NLnet, Google SoC) | ✅ (GitHub) | ✅ YES (LF/ACT) |

---

## Recommendations by Use Case

### For Code Hardener AI-Generated Code Scanning

**Top Recommendation: SCANOSS + scancode-toolkit (layered approach)**

1. **Primary: SCANOSS**
   - Native snippet detection engineered for AI-generated code fragments
   - Open-data knowledgebase approach (no proprietary training data)
   - Container support for scanning generated artifacts
   - Configurable tuning for different code patterns
   - Source: [SCANOSS Code Scan Action](https://github.com/marketplace/actions/scanoss-code-scan-action)

2. **Secondary: scancode-toolkit**
   - Line-level precision for detailed compliance reports
   - Apache-2.0 compatible licensing
   - Mature ecosystem with 2.4k stars
   - Excellent SPDX/CycloneDX export
   - Best for showing end-users exact code locations

3. **Supplementary: ORT**
   - Enterprise orchestration layer
   - Policy-as-code enforcement (via Rego/OPA integration in Code Hardener)
   - Multi-scanner coordination
   - Optional for advanced compliance workflows

### Avoid: licensee (for this use case)
- File-level detection insufficient for snippet-generated code
- No CI/CD containerization support
- Designed for project-level license identification, not code-level scanning

---

## Integration Points for Code Hardener

### MCP Server Implementation Strategy

Based on the orchestration flow in your CLAUDE.md (Phase 1 research → Phase 2 architecture → Phase 3 implementation):

1. **Research Phase Complete**: This analysis covers all four tools comprehensively
2. **Architecture Phase Next**:
   - Design MCP interface abstracting SCANOSS + scancode-toolkit
   - Define snippet detection output schema
   - Plan container orchestration (Kubernetes KEDA with gVisor/Firecracker sandbox)

3. **Implementation Phase**:
   - Primary scanner: SCANOSS (via Python CLI + ghcr.io container)
   - Secondary scanner: scancode-toolkit (via Docker container)
   - ORT integration optional for Phase 2+ (enterprise features)
   - Licensee: Skip for snippet detection, use only if project-level license needed

### Docker/Kubernetes Considerations
- **SCANOSS**: Use ghcr.io official image, supports file:// URLs with host bind mount
- **scancode-toolkit**: Use beevelop/scancode or build from Dockerfile, supports volume mounting
- **ORT**: Use ghcr.io/oss-review-toolkit/ort for orchestration layer
- **All**: Mount LOCAL_CODE_DIR for AI-generated code artifacts

---

## Sources

Primary Research Sources:

1. [SCANOSS Organization](https://github.com/scanoss)
2. [SCANOSS Code Scan Action](https://github.com/marketplace/actions/scanoss-code-scan-action)
3. [SCANOSS Snippet Matching Capabilities](https://oss-compliance-tooling.org/Tooling-Landscape/OSS-Based-License-Compliance-Tools/)
4. [SCANOSS License Compliance Understanding](https://www.scanoss.com/post/understanding-open-source-licence-compliance)
5. [SCANOSS Container Scanning](https://www.scanoss.com/post/introducing-container-scanning)
6. [ScanCode Toolkit - aboutcode-org/scancode-toolkit](https://github.com/aboutcode-org/scancode-toolkit)
7. [ScanCode License Detection Documentation](https://scancode-toolkit.readthedocs.io/en/stable/explanation/scancode-license-detection.html)
8. [ScanCode Releases](https://github.com/aboutcode-org/scancode-toolkit/releases)
9. [ScanCode.io CI/CD](https://scancodeio.readthedocs.io/en/latest/quickstart.html)
10. [licensee/licensee](https://github.com/licensee/licensee)
11. [ORT - oss-review-toolkit/ort](https://github.com/oss-review-toolkit/ort)
12. [ORT Documentation](https://oss-review-toolkit.github.io/ort/)
13. [ORT Snippet Choice Feature](http://oss-review-toolkit.org/ort/docs/configuration/snippet-choice)
14. [ORT License Handling](http://oss-review-toolkit.org/ort/docs/guides/license-handling)
15. [ORT GitLab CI Integration](https://github.com/oss-review-toolkit/ort-ci-gitlab)

---

**Document Status**: Complete research deliverable
**Next Phase**: Architecture specification (per orchestration flow)
