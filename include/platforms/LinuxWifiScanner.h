#pragma once

#include "WifiScanner.h"
#include <string>
#include <vector>

namespace WifiScanner {

class LinuxWifiScanner : public WifiScanner {
public:
    LinuxWifiScanner();
    ~LinuxWifiScanner() override;
    
    std::vector<NetworkInfo> scan() override;
    bool isSupported() const override;
    std::string getPlatformName() const override;
    
private:
    // Helper methods for Linux Wi-Fi scanning
    SecurityType parseSecurityType(const std::string& securityString) const;
    int parseSignalStrength(int rssi) const;
    int frequencyToChannel(int frequency) const;
    int channelToFrequency(int channel) const;
    
    // Alternative scanning methods
    std::vector<NetworkInfo> scanUsingIw() const;
    std::vector<NetworkInfo> scanInterfaceWithIw(const std::string& interface) const;
    std::vector<NetworkInfo> parseIwScanOutput(const std::string& output) const;
    std::vector<NetworkInfo> scanUsingNetworkManager() const;
    std::vector<NetworkInfo> parseNmcliOutput(const std::string& output) const;
    std::vector<NetworkInfo> scanUsingProcNet() const;
    
    // Enhanced security analysis methods
    bool detectGuestNetwork(const std::string& ssid) const;
    std::string extractVendorFromBSSID(const std::string& bssid) const;
    int estimateChannelWidth(int frequency) const;
    bool checkForPMF(const std::string& capabilities) const;
    bool checkForOWE(const std::string& capabilities) const;
    bool checkForWPS(const std::string& capabilities) const;
    int estimateDataRate(int frequency, int channelWidth) const;
};

} // namespace WifiScanner
