# Security Test Plan

The automated suite should verify:

1. Unknown agents and unauthorized operations are denied.
2. A blocked action never invokes its tool.
3. An unregistered tool cannot execute.
4. Derived artifacts inherit the highest source label.
5. Provenance survives save and reload.
6. Unknown labels and missing provenance are rejected.
7. Tampered artifact labels are detected.
8. Untrusted document instructions cannot change policy.
9. Audit records preserve the decision and execution outcome.

Run with:

```powershell
pytest -q
```

Tests must use temporary databases and must not deliver real messages.
