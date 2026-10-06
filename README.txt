Slice 12 r2 — cross-volume relative rename boundary

Purpose
-------
Verify that the Windows handle-relative rename primitive rejects a destination
directory on a different Windows volume with STATUS_NOT_SAME_DEVICE, without
falling back to copy/delete and without altering the source.

This is a standalone diagnostic/integration test. It uses the production
chrome_companion.win32_primitives implementation when available and contains
a low-level ctypes fallback so the diagnostic does not depend on an unreleased
production primitive.

Harness fixes from r1
---------------------
1. Added the missing `shutil` import used by cleanup.
2. Closed the DELETE-capable source HANDLE before pathname-based inspection.
   Python's normal pathname open can otherwise receive ERROR_ACCESS_DENIED
   because the still-open HANDLE has DELETE access. This was a test-harness
   sharing artifact, not evidence that the cross-volume rename succeeded.

No production source files are included or modified by this ZIP.

Run from the Lumina repository:
    pytest -q tests/test_chrome_companion_win32_cross_volume_rename.py

Expected result when a second accessible Windows volume is available:
    1 passed

If no second accessible Windows volume is available, the test skips cleanly.
