# Submission Template

## Folder Layout
```text
team-name/
  challenge-id/
    report.md
    iocs.json
    attack_map.md
    rules/
      yara/
      sigma/
    tool/        # optional
    evidence/    # screenshots/logs/pcaps
```

## report.md Sections
- Objective
- Methodology
- Findings
- Evidence List
- Reproduction Steps
- Conclusion

## iocs.json Minimum Fields
- sample_hashes (sha256)
- domains
- ip_addresses
- urls
- mutexes
- registry_keys
- file_paths
- process_names

## attack_map.md
- MITRE Technique ID
- Technique Name
- Evidence Reference
- Confidence (high/med/low)
