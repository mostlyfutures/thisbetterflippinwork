#pragma once

#include "WifiScanner.h"
#include <string>
#include <vector>

// Forward declarations for Windows types
struct _WLAN_INTERFACE_INFO_LIST;
struct _WLAN_AVAILABLE_NETWORK;
struct _WLAN_BSS_ENTRY;
typedef _WLAN_INTERFACE_INFO_LIST* PWLAN_INTERFACE_INFO_LIST;
typedef _WLAN_AVAILABLE_NETWORK* PWLAN_AVAILABLE_NETWORK;
typedef _WLAN_BSS_ENTRY* PWLAN_BSS_ENTRY;

namespace WifiScanner {

class WindowsWifiScanner : public WifiScanner {
public:
    WindowsWifiScanner();
    ~WindowsWifiScanner() override;
    
    std::vector<NetworkInfo> scan() override;
    bool isSupported() const override;
    std::string getPlatformName() const override;
    
private:
    // Windows WLAN client handle
    void* hClient_;
    
    // Helper methods for WlanAPI integration
    SecurityType parseSecurityType(unsigned long authType, unsigned long cipherType) const;
    int parseSignalStrength(int rssi) const;
    int frequencyToChannel(int frequency) const;
    int channelToFrequency(int channel) const;
    
    // Enhanced security analysis methods
    bool detectGuestNetwork(const std::string& ssid) const;
    std::string extractVendorFromBSSID(const std::string& bssid) const;
    int estimateChannelWidth(const PWLAN_BSS_ENTRY pBssEntry) const;
    bool checkForPMF(const PWLAN_AVAILABLE_NETWORK pNetwork) const;
    bool checkForOWE(const PWLAN_AVAILABLE_NETWORK pNetwork) const;
    bool checkForWPS(const PWLAN_AVAILABLE_NETWORK pNetwork) const;
    int estimateDataRate(int frequency, int channelWidth) const;
    
    // Rogue AP detection
    bool detectRogueAP(const NetworkInfo& current, const std::vector<NetworkInfo>& existing) const;
    bool isSimilarSSID(const std::string& ssid1, const std::string& ssid2) const;
};

} // namespace WifiScanner
