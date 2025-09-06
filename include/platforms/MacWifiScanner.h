#pragma once

#include "WifiScanner.h"
#include <string>
#include <vector>

namespace WifiScanner {

class MacWifiScanner : public WifiScanner {
public:
    MacWifiScanner();
    ~MacWifiScanner() override;
    
    std::vector<NetworkInfo> scan() override;
    bool isSupported() const override;
    std::string getPlatformName() const override;
    
private:
    // Helper methods for CoreWLAN integration
    SecurityType parseSecurityType(const std::string& securityString) const;
    SecurityType parseSecurityTypeFromCoreWLAN(int security) const;
    int parseSignalStrength(int rssi) const;
    int frequencyToChannel(int frequency) const;
    int channelToFrequency(int channel) const;
    
    // Enhanced security analysis methods
    bool detectGuestNetwork(const std::string& ssid) const;
    std::string extractVendorFromBSSID(const std::string& bssid) const;
    int estimateChannelWidth(const void* capabilities) const;
    bool checkForPMF(const void* capabilities) const;
    bool checkForOWE(const void* capabilities) const;
    int estimateDataRate(int frequency, int channelWidth) const;
};

} // namespace WifiScanner
