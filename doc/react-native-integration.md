# Android and React Native integration

## Scope and provenance

Local fork of XopProtector commit `a6c30b24ccdb844ac3a4e666af25fcbc36ace372`.
Duck source provenance and imported files are recorded in
`native/src/main/cpp/vendor/duck/UPSTREAM.json`. Copyright headers and the
Apache-2.0 license are retained. `self_process_ioc_probe.cpp` is adapted to report
unavailable reads as reduced coverage rather than two successful clean checks.
The RN host builder is adapted from RN 0.68 under its retained MIT license.

This is Android support for RN 0.68 old architecture / Hermes. There is no claim
of support for RN New Architecture, other RN versions, iOS, AAB delivery, Play
signing rotation, or OTA bundles. Each requires a separate adapter/test matrix.

## Build inputs

The adapter has been exercised with a React Native 0.68 / Hermes Android host
and a Java diagnostic-library AAR. Host application source, private build inputs,
artifacts and signing material are not part of this repository. The public fork
contains reusable protection code and synthetic policy tests only.

## Actual protection policy

The RN wrapper encrypts DEX and only `assets/index.android.bundle`. It disables
SO encryption, package hollowing, auto-VMP, resource renaming and network heuristics.
Java code from host AAR dependencies becomes part of the encrypted application
DEX. Host protocol code is not modified or selectively virtualized.

Native detectors run before DEX decryption and on a low-priority worker every
five seconds after initialization. The operation gate requests a fresh native
scan. It never reads or writes USB endpoints, sends USB ioctls, executes su,
scans default Frida ports, treats ADB enablement as root, or classifies a USB
connection as an attack. It does not request new Android permissions.

Imported passive Duck probes:

- Memory map parser and ART/JIT exclusions.
- Suspicious file-descriptor/memfd evidence (reading proc links only).
- Existing signal-handler ownership (query only; does not install handlers).
- Native root: self SELinux context and KSU descriptors; path confirmation;
  root-specific properties; exact process-name evidence; kernel indicators.
- LSPosed runtime maps.

A named executable instrumentation mapping, named Frida handler, or corroborated
suspicious memfd plus anonymous handler produces an instrumentation finding.
Broad `gadget` / temporary-path hints alone are not sufficient. Root requires a
self-runtime IOC or at least two independent source categories. A root property,
a path residue, an unavailable read, or an OEM kernel string alone is not enough.
Unavailable process visibility reduces coverage. It does not prove a clean device.
If self maps cannot be read, the operation gate cannot authorize a new write.

Not imported: timing/supercall probes, signal/FD/exit traps, privileged checks,
heap walking, early NativeActivity preload, isolated-process machinery, TEE and
attestation UI, dangerous-app inventory, virtualization traps. These are not
appropriate to copy indiscriminately into a host process with ongoing external operations. This is a
curated adapter, not the complete Duck diagnostic app. Name-based and
heuristic detection remains bypassable and needs continual empirical testing.

## Response and host operation boundary

`rasp_action=0` records findings. `1` latches restriction. Legacy `2` now has the
same nonfatal restriction semantics as `1`. Detector findings never deliberately
kill, ANR, disconnect USB, cancel a transfer, or execute a recovery command.
Loader corruption can still prevent startup; this policy cannot prevent arbitrary
runtime bugs or crashes.

The reusable module exposes `XopRaspModule.allowOperation(context, required)`.
The host must call it before starting an operation it chooses to protect. This
repository does not publish any private host application or its gate call sites.

A restriction must not interrupt an already-running transaction or prevent a
necessary recovery/continuation step. The host owns that transaction policy;
test it before enabling restriction. The adapter performs no automatic transfer
cancellation. Report-only mode is the default for gradual integration.

`XOP_REQUIRED=true` refuses new operations when the injected native runtime is
missing. The baseline build uses false. This is defense in depth, not a server
or external-system authorization boundary; a compromised process can attack host call sites.

## Bundle and Application compatibility

`XopBundleLoader.prepare` runs in the real Application before SoLoader startup.
It decrypts binary Hermes bytes into a 0600 file under a 0700 no-backup directory,
replacing the file atomically on every process start. Decryption failure does
not reuse an old file. The private plaintext remains present at runtime; this is
packaged-bundle protection, not a no-plaintext guarantee.

`XopReactNativeHost` uses `JSBundleLoader.createFileLoader` with the original
`assets://index.android.bundle` source URL. A plain getJSBundleFile override
changes RN image resolution and caused missing drawable images in the emulator;
the source-URL adapter fixes that behavior.

The packer requires `assets/xop-rn-adapter-v1` before accepting
`--encrypt-rn-bundle`. Other assets (fonts, configuration, images) remain
untouched. The shell still performs Application replacement and DEX classloader
merge; emulator checks must confirm the real ReactApplication identity.

## Xop compatibility fixes

- Windows optional UniMP paths no longer break macOS settings evaluation.
- The native shell links its C++ runtime statically with hidden static symbols;
  it does not overwrite RN's `libc++_shared.so`.
- A conflicting shell/app native-library basename now fails packing instead of
  silently overwriting the app library.
- DEX-only operation skips unnecessary ART and dlopen hooks and VMP initialization.
  Startup-injected Frida exposed an unconditional VMP initialization call that
  exited on restriction even with zero protected methods; this is now skipped.
  Optional protected methods still require hooks and are deliberately disabled
  in the RN wrapper.
- Shell D8 export includes Android's API library and an explicit minimum SDK.
- Native shell uses installed NDK 27 and 16 KB ELF link alignment. This does not
  upgrade the app's existing RN/third-party native libraries to 16 KB support.
- Weak port, timing, broad debugger, emulator, heartbeat-timeout, libc CRC and
  self-RWX/name-only dump-tool checks are removed from the RASP decision path.
- Shell section-integrity checking and authenticated configuration remain.
- Host protocol and library implementations remain outside this repository.

## Build and packaging

Test host: JDK 11, Gradle 7.3.3. Protector: tested using installed Gradle 8.7, JDK 21 and
NDK 27. The upstream Gradle 8.2 wrapper download timed out. JDK 17 dependency
requests had TLS handshake failures; JDK 21 resolved them without disabling TLS.

Build the host app and its dependencies using their own supported toolchain.
Build Xop with `:packer:test :packer:jar exportShellFiles`.
Run portable policy regressions with `scripts/test-rn-policy.sh`.

Run `scripts/protect-rn.py INPUT OUTPUT --cert-sha256 FINAL_SIGNER_SHA256`.
The default mode is report. `--mode restrict` is for isolated enforcement tests.
The output is unsigned. Run SDK `zipalign -P 16` before signing, then `apksigner
verify` and `zipalign -c -P 16`. Do not use the production artifact path as output.

Use a dedicated test signer for evaluation artifacts. An APK cannot update an
installation signed with an unrelated certificate. Never commit signing keys,
passwords, protected customer APKs or runtime captures.

## Validation

Validation on an isolated API 35 arm64 emulator: 35 packer tests and portable
native policy regressions passed; cold/warm RN startup rendered the expected
screen. Existing host native libraries and non-bundle assets remained unchanged.
Frida 17.17.0 startup injection reached the real Application and returned the
expected report/restrict gate decisions. No physical peripheral, transaction recovery,
root-framework matrix or authenticated backend qualification has been performed.
Private host logs and artifacts are intentionally excluded. These observations
are not proof of safe operation of a host application or comprehensive root detection.

Required qualification before enforcement:

1. Supported physical OEM devices: clean/locked, developer settings on/off.
2. Peripheral attach/detach/reconnect, permissions, background/resume and suspension.
3. Frida startup/late attachment, renamed variants, Gadget, supported root frameworks
   and LSPosed, recording both detection and unavailable probe coverage.
4. Threat before, during and between multi-stage operations; preserve required
   continuation and recovery paths. Do not infer safety from a process-survival test.
5. Cold/warm startup, upgrade, Android API 28 and every supported ABI. Assess
   third-party native dependencies and 16 KB compatibility separately.
6. Detector scan duration/CPU and host latency. Synthetic policy tests cannot
   establish a zero false-positive rate.

## Open instrumentation regression

Repeated late attachment through Frida 17.17.0's Java bridge failed in both
protected modes, followed by an ART DetachCurrentThread crash with frida-agent
frames. Two unprotected baseline checks passed. The stack does not establish
whether this is a Frida/ART issue or an interaction with the protected loader.
It remains unresolved and is not a restriction-only failure. Final startup/gate
checks passed; those successes do not erase the late-attachment failures.
A passive late attachment without the Java bridge recorded instrumentation and
preserved the process during a 12-second observation and after detach.

## Local key limitations

DEX and bundle payloads use AES-128-GCM with keys recoverable from the APK's
native loader. Keys are XOR-masked with constants shipped in the implementation;
the inherited loader code-section wrapping uses RC4. These layers increase the
work of straightforward inspection but do not establish a secret unavailable to
an APK-only analyst. No server-held or device-bound secret is required. DEX is
decrypted as a whole on cold startup and cached privately; this wrapper does not
perform per-method just-in-time decryption. Runtime findings cannot prevent
offline analysis of the distributed APK.
