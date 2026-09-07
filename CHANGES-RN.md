# Changes from upstream

This fork modifies XopProtector at a6c30b24ccdb844ac3a4e666af25fcbc36ace372.

- Adds a React Native 0.68 / Hermes Android package with bundle loading, status,
  threat reporting and a native operation gate. Preserves the bundle source URL
  so packaged images continue to resolve.
- Adds bundle-only encryption, an adapter marker check and regression tests.
- Replaces environmental RASP/root heuristics with selected passive Duck probes
  and an evidence policy; retains shell-integrity mechanisms. Findings report
  or restrict rather than deliberately terminating a running transfer.
- Skips ART/dlopen hooks and unnecessary VMP initialization for DEX-only mode.
- Prevents native-library collisions and uses a static C++ runtime for the shell.
- Fixes optional Windows paths in Gradle on macOS and supplies the Android API
  library/minimum API to shell D8 export. Native build uses NDK 27.
- Retains Apache-2.0 licensing and upstream attributions. The imported Duck
  self-process probe reports unavailable reads as reduced coverage; its precise
  provenance is recorded alongside the vendored source.

Known limits: recoverable APK-local keys; private plaintext runtime cache;
unresolved Frida Java-bridge late-attach crash; no physical host/peripheral qualification;
no claim for other RN versions, New Architecture, iOS, AAB or OTA delivery.
