---
name: Benchmark defect / 试卷或工具缺陷
about: Evidence-based report, not a request to lower difficulty for one workflow
title: '[Task ID / tool] '
labels: ''
assignees: ''
---

## Version and component

Task ID, commit/distribution lock, runner/environment identity (if applicable):

## Expected vs observed

Which public requirement is contradicted? Distinguish input ambiguity, adapter,
runtime INFRA, evaluator and scoring issues. A low workflow score alone is not a defect.

## Minimal public reproducer

Commands, tool versions, sanitized summary. Do not upload secrets, private paths,
raw model responses, reference RTL or hidden tests. Ask for a private review channel
if the reproducer requires evaluator-private material.

## Suggested fix and validation

Failing regression, expected unaffected cases, calibration/repeatability checks,
version impact and which comparable runs must restart:
