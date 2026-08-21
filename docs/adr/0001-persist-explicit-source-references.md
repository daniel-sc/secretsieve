# Persist Explicit Source References

Known Sources are setup-time discovery knowledge only. Enrollment persists an
explicit resolver type, path, and selector rather than a Known Source identity,
so runtime behavior remains inspectable and cannot change when a maintained
discovery definition changes. Persisting a Known Source identity would follow
path overrides and schema updates automatically, but it would also make an
existing configuration read new locations or fields after an upgrade. Path
overrides are therefore resolved during setup, and users rerun setup when those
overrides change.
