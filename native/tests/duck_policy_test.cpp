#include "risk/duck_policy.h"
#include "memory/detectors/fd_detector.h"
#include <cassert>
#include <iostream>

using namespace protector::risk::duck;
int main() {
    // Ordinary USB, ADB, diagnostic serial devices and RN runtime are not findings.
    for (auto path : {"/dev/bus/usb/001/002", "/dev/usb-ffs/adb/ep1",
                      "/dev/ttyACM0", "/dev/ttyUSB0", "/dev/usb_gadget",
                      "/system/bin/adbd", "socket:[27042]",
                      "/data/app/app/lib/arm64/libhermes.so",
                      "/data/app/app/lib/arm64/libreactnativejni.so",
                      "/memfd:jit-cache (deleted)", "/data/app/gadget/lib/arm64/libvehicle.so"}) {
        assert(!named_instrumentation(path));
    }
    assert(named_instrumentation("/data/app/app/lib/arm64/libfrida-gadget.so"));
    assert(named_instrumentation("/data/local/tmp/frida-agent-64.so"));
    assert(named_instrumentation("/memfd:frida-agent-64.so (deleted)"));
    Evidence e;
    assert(!root(e) && !instrumentation(e));
    assert(!may_start(false, false, true));
    assert(!may_start(true, false, false)); // Unavailable != clean authorization.
    assert(may_start(true, false, true));
    assert(!may_start(true, true, true));
    e.root_property = true;
    assert(!root(e));
    e.root_path = true;
    assert(root(e));
    e = {}; e.root_runtime = true;
    assert(root(e));
    e = {}; e.suspicious_memfd = true;
    assert(!instrumentation(e));
    e.anonymous_handler = true;
    assert(instrumentation(e));
    e = {}; e.instrumentation_mapping = true;
    assert(instrumentation(e));
    // The upstream FD probe must not classify normal USB nodes or ART JIT maps.
    std::vector<duckdetector::memory::MapEntry> maps;
    for (auto path : {"/dev/bus/usb/001/002", "/dev/ttyUSB0", "/memfd:jit-cache (deleted)"}) {
        duckdetector::memory::MapEntry m;
        m.executable = true; m.path = path; maps.push_back(m);
    }
    auto fd = duckdetector::memory::detect_fd_anomalies(maps);
    assert(!fd.suspicious_memfd && !fd.deleted_so && !fd.exec_ashmem && !fd.dev_zero_exec);
    std::cout << "Duck policy regressions passed\n";
}
