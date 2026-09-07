#include "risk/risk.h"
#include "risk/so_guard.h"
#include "risk/duck_detector.h"
#include "risk/duck_policy.h"
#include "report/threat_report.h"
#include "common/runtime_state.h"
#include "common/log.h"
#include "common/protector_macro.h"
#include <atomic>
#include <cstdlib>
#include <mutex>
#include <set>
#include <string>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <sys/resource.h>

namespace protector::risk {
static std::atomic_bool g_started{false};
static std::atomic_bool g_delayed_crash{false};
static const char* g_crash_reason = "runtime_invariant";

// Vehicle-safe response: never deliberately kill a live transport on a finding.
// Block (legacy value 2) also latches restriction; host gates new operations.
PROTECTOR_ENCRYPT void handle_risk(const char* reason, CrashKind) {
    int action = runtime_state().config.rasp_action.load();
    if (action != static_cast<int>(RaspAction::Alert))
        runtime_state().environment_degraded.store(true, std::memory_order_release);
    static std::mutex report_mutex;
    static std::set<std::string> reported;
    std::lock_guard<std::mutex> lock(report_mutex);
    if (reported.insert(reason ? reason : "unknown").second)
        report::report_threat(reason ? reason : "unknown", action);
}

// Fatal primitives remain solely for unrecoverable loader/integrity invariants.
PROTECTOR_ENCRYPT void crash_sigill() {
#ifdef DEBUG
    PLOGE("risk: sigill reason=%s", g_crash_reason);
    abort();
#else
    __android_log_print(ANDROID_LOG_ERROR, "protector.risk", "sigill reason=%s", g_crash_reason);
    // udf/#0 on arm64 → SIGILL; attacker can catch but not easily resume
    __builtin_trap();
#endif
}

PROTECTOR_ENCRYPT void crash_sigsegv() {
#ifdef DEBUG
    PLOGE("risk: sigsegv reason=%s", g_crash_reason);
    abort();
#else
    __android_log_print(ANDROID_LOG_ERROR, "protector.risk", "sigsegv reason=%s", g_crash_reason);
    // Null deref → SIGSEGV. Different signal, different handler bypass.
    volatile int* p = nullptr;
    *p = 0xDEAD;
    // If we somehow survive, force a trap
    __builtin_trap();
#endif
}

PROTECTOR_ENCRYPT void crash_abort() {
    // Always use real abort() — generates SIGABRT with a distinct
    // tombstone backtrace that doesn't point back to detection code.
    PLOGE("risk: abort");
    abort();
}

PROTECTOR_ENCRYPT void crash_hang() { abort(); }

PROTECTOR_ENCRYPT void crash_exit() {
    // Clean _exit: no tombstone, no crash log, process just disappears.
    // Much harder to diagnose than a signal.
    _exit(1);
}

PROTECTOR_ENCRYPT
void schedule_delayed_crash() { g_delayed_crash.store(true); }
void check_delayed_crash() {
    if (g_delayed_crash.exchange(false)) handle_risk("deferred_integrity", CrashKind::Exit);
}
void crash_on_risk() { handle_risk("legacy_risk", CrashKind::Exit); }
// A suspended Android process may miss a heartbeat. This is not attack evidence.
void record_java_heartbeat() {}
void scan_hooks_and_frida_now() {
    scan_duck_detectors();
    so_guard_check();
}
bool can_start_sensitive_operation() {
    if (!runtime_state().inited.load(std::memory_order_acquire)) return false;
    scan_hooks_and_frida_now();
    return duck::may_start(true, runtime_state().environment_degraded.load(),
                          duck_maps_available());
}
bool vmp_allowed() {
    auto& state = runtime_state();
    if (state.environment_degraded.load(std::memory_order_acquire)) {
        return false;
    }
    // Periodic light SO pulse (every 64th TRUE_VMP call) without scanning Frida every time.
    static std::atomic<uint32_t> tick{0};
    uint32_t n = tick.fetch_add(1, std::memory_order_relaxed);
    if ((n & 63u) == 0u) {
        int flags = state.config.risk_flags.load(std::memory_order_relaxed);
        if ((flags & FLAG_DISABLE_SO_INTEGRITY) == 0) {
            so_guard_check();
        }
        if (state.environment_degraded.load(std::memory_order_acquire)) {
            return false;
        }
    }
    return true;
}


static void* risk_thread_main(void*) {
    setpriority(PRIO_PROCESS, 0, 10); // Linux nice is per-thread; preserve transport priority.
    while (true) {
        // Constructor runs before authenticated config; don't classify bootstrap.
        if (runtime_state().inited.load(std::memory_order_acquire)) {
            scan_hooks_and_frida_now();
            check_delayed_crash();
        }
        sleep(5);
    }
    return nullptr;
}
void DefaultRiskChecker::start() {
    bool expected = false;
    if (!g_started.compare_exchange_strong(expected, true)) return;
    pthread_t thread;
    if (pthread_create(&thread, nullptr, risk_thread_main, nullptr) == 0)
        pthread_detach(thread);
    else {
        g_started.store(false);
        handle_risk("monitor_start_failed", CrashKind::Exit);
    }
}
RiskChecker& risk_checker() { static DefaultRiskChecker checker; return checker; }
} // namespace protector::risk
