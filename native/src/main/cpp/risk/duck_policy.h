#pragma once
#include <string>
#include "memory/common/maps_reader.h"

namespace protector::risk::duck {
// Duck's broad "gadget" / tmp-path hints are not proof of instrumentation.
// In particular USB gadget device nodes and ADB are not attack evidence.
inline bool named_instrumentation(const std::string& path) {
    const auto p = duckdetector::memory::to_lower_ascii(path);
    if (!duckdetector::memory::is_suspicious_loader_path(p)) return false;
    const auto name = duckdetector::memory::basename_of(p);
    return name == "frida-agent-64.so" || name == "frida-agent-32.so"
        || name == "frida-agent.so" || name == "libfrida-gadget.so"
        || name == "frida-gadget.so"
        || name.rfind("memfd:frida", 0) == 0
        || name.rfind("memfd:re.frida", 0) == 0
        || name == "libfrida-gadget.so (deleted)"
        || name == "frida-agent.so (deleted)";
}
struct Evidence {
    bool maps_available = false;
    bool instrumentation_mapping = false;
    bool instrumentation_handler = false;
    bool suspicious_memfd = false;
    bool anonymous_handler = false;
    bool root_runtime = false;
    bool root_path = false;
    bool root_property = false;
    bool root_process = false;
    bool root_kernel = false;
    bool lsposed_mapping = false;
};
inline bool instrumentation(const Evidence& e) {
    return e.instrumentation_mapping || e.instrumentation_handler
        || (e.suspicious_memfd && e.anonymous_handler);
}
inline bool root(const Evidence& e) {
    return e.root_runtime || (static_cast<int>(e.root_path) + e.root_property
        + e.root_process + e.root_kernel >= 2);
}
inline bool may_start(bool initialized, bool degraded, bool maps_available) {
    return initialized && !degraded && maps_available;
}
}
