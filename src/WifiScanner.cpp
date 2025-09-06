#include "WifiScanner.h"

#ifdef _WIN32
#include "platforms/WindowsWifiScanner.h"
#elif defined(__APPLE__)
#include "platforms/MacWifiScanner.h"
#elif defined(__linux__)
#include "platforms/LinuxWifiScanner.h"
#else
#include <iostream>
#endif

namespace WifiScanner {

std::unique_ptr<WifiScanner> createWifiScanner() {
#ifdef _WIN32
    return std::make_unique<WindowsWifiScanner>();
#elif defined(__APPLE__)
    return std::make_unique<MacWifiScanner>();
#elif defined(__linux__)
    return std::make_unique<LinuxWifiScanner>();
#else
    // Fallback for unsupported platforms
    std::cerr << "Warning: Wi-Fi scanning not supported on this platform" << std::endl;
    return nullptr;
#endif
}

} // namespace WifiScanner
