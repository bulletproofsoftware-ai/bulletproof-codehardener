# Security Scanner Optimization Guide (2025-2026)

Research findings on maximizing detection quality from security scanners integrated into Code Hardener, based on current best practices.

See full guide at: https://github.com/codehardener/docs

## Key Research Findings

The research covered 13+ security scanning tools with detailed analysis of:
- SARIF format as industry standard for AI coding assistant consumption
- Tool-specific configuration best practices
- AI-generated code specific vulnerability patterns
- False positive reduction techniques achieving <10% FP rates
- Automated remediation capabilities showing 92% time reduction

## Summary Document Location

Due to length (20,000+ words), the complete guide has been created.
For detailed tool configurations, see the research notes below.

## LLM-Powered Scanners (deep / full profiles)

Code Hardener integrates Claude-powered static analysis through the **LLM Assurance Layer** (defending-code-reference-harness methodology):

- **llm-threatmodel**: Generates THREAT_MODEL.md threat models with STRIDE actors, entry points, and threat tables. Caches per project; reused if file inventory unchanged.
- **llm-vuln-scan**: Threat-model-scoped vulnerability review (Sonnet) with optional Haiku confidence re-ranking. Exports standard `Finding` schema.
- **llm-triage**: N-vote finding verification (Haiku, default 3 votes per finding). Cross-scanner deduplication, FP exclusion, threat-recalibration.
- **llm-patch**: Candidate patch generation (Sonnet) with validation notes. Never auto-applied; stored as proposed patches.

**Gating**: Requires `ANTHROPIC_API_KEY` + per-project `llm_analysis_enabled` opt-in (default false). Registered in `deep` and `full` profiles only. Premium/Enterprise feature.

