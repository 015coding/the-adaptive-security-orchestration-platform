# Hybrid evidence storage

The Owner host stores Findings, Evidence Records, provenance, integrity hashes, and searchable metadata. Large or raw artifacts, including memory images, remain as VM-Resident Artifacts in the appropriate Run Workspace and are referenced from the host rather than copied into SQLite or host evidence storage. Cleanup never deletes the host-side record: unavailable artifacts are marked with their last-known location, and the Owner may archive selected artifacts before cleanup.
