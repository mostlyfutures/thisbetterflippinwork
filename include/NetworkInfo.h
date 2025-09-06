#pragma once

#include <string>
#include <vector>

namespace WifiScanner {

enum class SecurityType {
    OPEN,
    WEP,
    WPA,
    WPA2_PERSONAL,
    WPA2_ENTERPRISE,
    WPA3_PERSONAL,
    WPA3_ENTERPRISE,
    UNKNOWN
};

enum class SecurityGrade {
    VERY_BAD,
    BAD,
    OKAY,
    GOOD,
    EXCELLENT
};

struct NetworkInfo {
    std::string ssid;
    std::string bssid;
    SecurityType securityType;
    int signalStrength;  // RSSI in dBm
    int channel;
    int frequency;       // MHz
    bool isHidden;
    std::string capabilities;
    
    // Additional security factors
    int channelWidth;    // MHz (20, 40, 80, 160)
    bool isEnterprise;   // Enterprise vs Personal authentication
    bool supportsWPS;    // Wi-Fi Protected Setup
    bool supportsPMF;    // Protected Management Frames
    bool supportsOWE;    // Opportunistic Wireless Encryption
    int maxDataRate;     // Mbps
    std::string vendor;  // Router/AP vendor if detectable
    bool isGuestNetwork; // Likely guest network based on SSID patterns
    
    // Advanced security analysis
    bool isRogueAP;      // Potential rogue access point
    bool isEvilTwin;     // Same SSID, different BSSID
    bool isTypoSquatting; // Very similar SSID
    int beaconInterval;  // Beacon frame interval (ms)
    bool respondsToProbes; // Responds to all probe requests
    bool hasAnomalousBehavior; // Unusual network behavior
    
    NetworkInfo() : signalStrength(0), channel(0), frequency(0), isHidden(false),
                    channelWidth(20), isEnterprise(false), supportsWPS(false),
                    supportsPMF(false), supportsOWE(false), maxDataRate(0), isGuestNetwork(false),
                    isRogueAP(false), isEvilTwin(false), isTypoSquatting(false),
                    beaconInterval(100), respondsToProbes(false), hasAnomalousBehavior(false) {}
};

} // namespace WifiScanner
