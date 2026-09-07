#pragma once

#include <cstdint>
#include <atomic>

namespace protector::risk {

/** Align with dpt-shell risk_check_flags bit meanings. */
constexpr int FLAG_DISABLE_FRIDA_DETECT = 1 << 0;
constexpr int FLAG_DISABLE_CRC_DETECT = 1 << 1;
constexpr int FLAG_DISABLE_ANTI_DEBUG = 1 << 2;
constexpr int FLAG_DISABLE_XPOSED_DETECT = 1 << 3;
constexpr int FLAG_DISABLE_ROOT_DETECT = 1 << 4;
constexpr int FLAG_DISABLE_EMULATOR_DETECT = 1 << 5;
/** Disable libprotector .bitcode CRC / anti-dump map checks (so_guard). */
constexpr int FLAG_DISABLE_SO_INTEGRITY = 1 << 6;

/** RN fork: root on; emulator, legacy port/CRC/debug heuristics removed. */
constexpr int DEFAULT_RISK_FLAGS =
        FLAG_DISABLE_EMULATOR_DETECT;

class RiskChecker {
public:
    virtual ~RiskChecker() = default;
    virtual void start() {}
};

/** Passive Duck evidence + shell integrity on a background thread. */
class DefaultRiskChecker : public RiskChecker {
public:
    void start() override;
};

RiskChecker& risk_checker();

/** Run a fast Frida/hook screen on the calling thread (init_app / JNI). */
void scan_hooks_and_frida_now();
bool can_start_sensitive_operation();

/**
 * Gate for TRUE_VMP interpret(). Returns false when RASP has marked the
 * environment degraded (Alert/Block may still allow; Degrade refuses).
 * Optionally triggers a light SO integrity pulse every N calls.
 */
bool vmp_allowed();

/** Crash kind for RASP Block mode (diverse tombstones / exits). */
enum class CrashKind {
    SigIll,
    SigSegv,
    Abort,
    Hang,
    Exit,
};

/**
 * Central RASP gate: respects config.rasp_action
 *   Alert(0)   — log only
 *   Degrade(1) — set environment_degraded only (app may refuse sensitive ops)
 *   Block(2)   — compatibility alias for Degrade; never kill a live transport
 */
void handle_risk(const char* reason, CrashKind kind);

// ── Diverse crash paths ─────────────────────────────────────────────

/** Illegal instruction (__builtin_trap / udf#0).  Used for hook/CRC. */
void crash_sigill();

/** Null deref → SIGSEGV.  Used for Frida / debugger detection. */
void crash_sigsegv();

/** abort() → SIGABRT.  Used for signature verification failure. */
void crash_abort();

/** Legacy fatal loader failure. Aborts instead of spinning indefinitely. */
void crash_hang();

/** _exit(1) — clean exit, no tombstone.  Used for config integrity. */
void crash_exit();

void schedule_delayed_crash();
void check_delayed_crash();

[[deprecated("Use a specific crash_* variant")]]
void crash_on_risk();

void record_java_heartbeat();

} // namespace protector::risk
