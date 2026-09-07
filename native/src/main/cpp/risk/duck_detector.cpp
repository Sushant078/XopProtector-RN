#include "risk/duck_detector.h"
#include "risk/duck_policy.h"
#include "risk/risk.h"
#include "common/runtime_state.h"
#include "report/threat_report.h"
#include "memory/detectors/fd_detector.h"
#include "memory/detectors/signal_detector.h"
#include "nativeroot/probes/self_process_ioc_probe.h"
#include "nativeroot/probes/path_probe.h"
#include "nativeroot/probes/property_probe.h"
#include "lsposed/probes/maps_probe.h"
#include "nativeroot/probes/process_probe.h"
#include "nativeroot/probes/kernel_probe.h"
#include <atomic>
#include <mutex>

namespace protector::risk {
static std::mutex scan_mutex;
static std::atomic_bool maps_available{false};
bool duck_maps_available() { return maps_available.load(std::memory_order_acquire); }

void scan_duck_detectors() {
    std::lock_guard<std::mutex> lock(scan_mutex);
    const int flags = runtime_state().config.risk_flags.load();
    duck::Evidence e;
    const auto maps = duckdetector::memory::read_self_maps();
    e.maps_available = !maps.empty();
    maps_available.store(e.maps_available, std::memory_order_release);
    if (!e.maps_available) {
        // Coverage failure is not a root finding. A new write cannot be authorized.
        static bool reported = false;
        if (!reported) report::report_threat("duck_maps_unavailable", 0);
        reported = true;
        return;
    }
    if (!(flags & FLAG_DISABLE_FRIDA_DETECT)) {
        for (const auto& map : maps) {
            if (map.executable && duck::named_instrumentation(map.path))
                e.instrumentation_mapping = true;
        }
        // Read existing handlers only: never install traps or modify handlers.
        const auto signals = duckdetector::memory::detect_signal_anomalies(maps);
        const auto fds = duckdetector::memory::detect_fd_anomalies(maps);
        e.instrumentation_handler = signals.frida_named_handler;
        e.anonymous_handler = signals.anonymous_handler;
        e.suspicious_memfd = fds.suspicious_memfd;
        if (duck::instrumentation(e)) handle_risk("duck_instrumentation", CrashKind::Exit);
    }
    if (!(flags & FLAG_DISABLE_XPOSED_DETECT)) {
        const auto lsposed = duckdetector::lsposed::scan_runtime_maps();
        e.lsposed_mapping = lsposed.available && lsposed.hit_count > 0;
        if (e.lsposed_mapping) handle_risk("duck_lsposed_runtime", CrashKind::Exit);
    }
    if (!(flags & FLAG_DISABLE_ROOT_DETECT)) {
        const auto self = duckdetector::nativeroot::run_self_process_ioc_probe();
        const auto paths = duckdetector::nativeroot::run_path_probe();
        const auto props = duckdetector::nativeroot::run_property_probe();
        const auto processes = duckdetector::nativeroot::run_process_probe();
        const auto kernel = duckdetector::nativeroot::run_kernel_probe();
        e.root_process = processes.flags.kernel_su || processes.flags.magisk || processes.flags.apatch;
        e.root_kernel = kernel.flags.kernel_su || kernel.flags.magisk || kernel.flags.apatch;
        e.root_runtime = self.flags.kernel_su;
        e.root_path = paths.flags.kernel_su || paths.flags.magisk || paths.flags.apatch;
        e.root_property = props.flags.kernel_su || props.flags.magisk || props.flags.apatch;
        if (duck::root(e)) handle_risk("duck_root_corroborated", CrashKind::Exit);
        else if (e.root_path || e.root_property || e.root_process || e.root_kernel) {
            static bool reported = false;
            if (!reported) report::report_threat("duck_root_supporting_only", 0);
            reported = true;
        }
    }
}
}
