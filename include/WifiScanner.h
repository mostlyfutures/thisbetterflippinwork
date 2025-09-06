#pragma once

#include "NetworkInfo.h"
#include <vector>
#include <memory>

namespace WifiScanner {

class WifiScanner {
public:
    virtual ~WifiScanner() = default;
    
    // Scan for available networks
    virtual std::vector<NetworkInfo> scan() = 0;
    
    // Check if scanning is supported on this platform
    virtual bool isSupported() const = 0;
    
    // Get platform name
    virtual std::string getPlatformName() const = 0;
};

// Factory function to create appropriate scanner for current platform
std::unique_ptr<WifiScanner> createWifiScanner();

} // namespace WifiScanner
