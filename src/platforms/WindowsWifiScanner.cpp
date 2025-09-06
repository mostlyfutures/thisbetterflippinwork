#include "platforms/WindowsWifiScanner.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <regex>
#include <windows.h>
#include <wlanapi.h>
#include <objbase.h>
#include <wtypes.h>
#include <iphlpapi.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace WifiScanner {

WindowsWifiScanner::WindowsWifiScanner() : hClient_(NULL) {
    // Initialize COM for WlanAPI
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    
    // Open WLAN client handle
    DWORD dwMaxClient = 2;
    DWORD dwCurVersion = 0;
    DWORD dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient_);
    
    if (dwResult != ERROR_SUCCESS) {
        std::cerr << "Failed to open WLAN client handle. Error: " << dwResult << std::endl;
    }
}

WindowsWifiScanner::~WindowsWifiScanner() {
    if (hClient_) {
        WlanCloseHandle(hClient_, NULL);
    }
    CoUninitialize();
}

std::vector<NetworkInfo> WindowsWifiScanner::scan() {
    std::vector<NetworkInfo> networks;
    
    if (!hClient_) {
        std::cerr << "WLAN client not initialized" << std::endl;
        return networks;
    }
    
    // Get list of interfaces
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    DWORD dwResult = WlanEnumInterfaces(hClient_, NULL, &pIfList);
    
    if (dwResult != ERROR_SUCCESS) {
        std::cerr << "Failed to enumerate WLAN interfaces. Error: " << dwResult << std::endl;
        return networks;
    }
    
    // Scan each interface
    for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
        PWLAN_INTERFACE_INFO pIfInfo = &pIfList->InterfaceInfo[i];
        
        // Trigger scan on this interface
        WlanScan(hClient_, &pIfInfo->InterfaceGuid, NULL, NULL, NULL);
        
        // Wait a bit for scan to complete
        Sleep(2000);
        
        // Get available networks
        PWLAN_AVAILABLE_NETWORK_LIST pBssList = NULL;
        dwResult = WlanGetAvailableNetworkList(hClient_, &pIfInfo->InterfaceGuid, 
                                             0, NULL, &pBssList);
        
        if (dwResult == ERROR_SUCCESS) {
            // Process each network
            for (DWORD j = 0; j < pBssList->dwNumberOfItems; j++) {
                PWLAN_AVAILABLE_NETWORK pBssEntry = &pBssList->wlanAvailableNetwork[j];
                
                NetworkInfo info;
                
                // SSID
                if (pBssEntry->dot11Ssid.uSSIDLength > 0) {
                    info.ssid = std::string((char*)pBssEntry->dot11Ssid.ucSSID, 
                                          pBssEntry->dot11Ssid.uSSIDLength);
                }
                
                // Security type
                info.securityType = parseSecurityType(pBssEntry->dot11DefaultAuthType, 
                                                   pBssEntry->dot11DefaultCipherType);
                
                // Enterprise vs Personal
                info.isEnterprise = (pBssEntry->dot11DefaultAuthType == DOT11_AUTH_ALGO_RSNA ||
                                   pBssEntry->dot11DefaultAuthType == DOT11_AUTH_ALGO_WPA);
                
                // Hidden network
                info.isHidden = (pBssEntry->bNetworkConnectable == FALSE);
                
                // Guest network detection
                info.isGuestNetwork = detectGuestNetwork(info.ssid);
                
                // Get detailed BSS information for signal strength and BSSID
                PWLAN_BSS_LIST pBssDetailList = NULL;
                dwResult = WlanGetNetworkBssList(hClient_, &pIfInfo->InterfaceGuid,
                                               &pBssEntry->dot11Ssid,
                                               pBssEntry->dot11BssType,
                                               TRUE, NULL, &pBssDetailList);
                
                if (dwResult == ERROR_SUCCESS && pBssDetailList->dwNumberOfItems > 0) {
                    PWLAN_BSS_ENTRY pBssDetail = &pBssDetailList->wlanBssEntry[0];
                    
                    // BSSID
                    std::stringstream bssid;
                    for (int k = 0; k < 6; k++) {
                        if (k > 0) bssid << ":";
                        bssid << std::hex << std::setw(2) << std::setfill('0') 
                              << (int)pBssDetail->dot11Bssid[k];
                    }
                    info.bssid = bssid.str();
                    
                    // Signal strength (RSSI)
                    info.signalStrength = pBssDetail->lRssi;
                    
                    // Channel
                    info.channel = pBssDetail->uChCenterFreq;
                    
                    // Frequency
                    info.frequency = channelToFrequency(info.channel);
                    
                    // Vendor detection
                    info.vendor = extractVendorFromBSSID(info.bssid);
                    
                    // Channel width estimation
                    info.channelWidth = estimateChannelWidth(pBssDetail);
                    
                    // Security features
                    info.supportsPMF = checkForPMF(pBssEntry);
                    info.supportsOWE = checkForOWE(pBssEntry);
                    info.supportsWPS = checkForWPS(pBssEntry);
                    
                    // Data rate estimation
                    info.maxDataRate = estimateDataRate(info.frequency, info.channelWidth);
                    
                    // Rogue AP detection
                    info.isRogueAP = detectRogueAP(info, networks);
                    
                    WlanFreeMemory(pBssDetailList);
                }
                
                networks.push_back(info);
            }
            
            WlanFreeMemory(pBssList);
        }
    }
    
    WlanFreeMemory(pIfList);
    return networks;
}

bool WindowsWifiScanner::isSupported() const {
    return hClient_ != NULL;
}

std::string WindowsWifiScanner::getPlatformName() const {
    return "Windows";
}

SecurityType WindowsWifiScanner::parseSecurityType(DWORD authType, DWORD cipherType) const {
    switch (authType) {
        case DOT11_AUTH_ALGO_80211_OPEN:
            return SecurityType::OPEN;
        case DOT11_AUTH_ALGO_80211_SHARED_KEY:
            return SecurityType::WEP;
        case DOT11_AUTH_ALGO_RSNA:
            if (cipherType == DOT11_CIPHER_ALGO_CCMP) {
                return SecurityType::WPA2_PERSONAL;
            } else if (cipherType == DOT11_CIPHER_ALGO_TKIP) {
                return SecurityType::WPA2_PERSONAL;
            }
            return SecurityType::WPA2_PERSONAL;
        case DOT11_AUTH_ALGO_WPA:
            if (cipherType == DOT11_CIPHER_ALGO_TKIP) {
                return SecurityType::WPA;
            }
            return SecurityType::WPA;
        case DOT11_AUTH_ALGO_WPA_PSK:
            return SecurityType::WPA2_PERSONAL;
        case DOT11_AUTH_ALGO_WPA_NONE:
            return SecurityType::WPA;
        default:
            return SecurityType::UNKNOWN;
    }
}

int WindowsWifiScanner::parseSignalStrength(int rssi) const {
    return rssi;
}

int WindowsWifiScanner::frequencyToChannel(int frequency) const {
    if (frequency >= 2412 && frequency <= 2484) {
        return (frequency - 2412) / 5 + 1;
    } else if (frequency >= 5170 && frequency <= 5825) {
        return (frequency - 5170) / 5 + 34;
    }
    return 0;
}

int WindowsWifiScanner::channelToFrequency(int channel) const {
    if (channel >= 1 && channel <= 13) {
        return 2407 + (channel * 5);
    } else if (channel >= 34 && channel <= 165) {
        return 5000 + (channel * 5);
    }
    return 0;
}

bool WindowsWifiScanner::detectGuestNetwork(const std::string& ssid) const {
    std::string lowerSSID = ssid;
    std::transform(lowerSSID.begin(), lowerSSID.end(), lowerSSID.begin(), ::tolower);
    
    std::vector<std::string> guestPatterns = {
        "guest", "visitor", "public", "hotel", "cafe", "restaurant",
        "airport", "mall", "library", "university", "college",
        "temporary", "temp", "test", "demo", "free", "open"
    };
    
    for (const auto& pattern : guestPatterns) {
        if (lowerSSID.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

std::string WindowsWifiScanner::extractVendorFromBSSID(const std::string& bssid) const {
    if (bssid.length() < 17) return "";
    
    // Extract OUI (first 6 characters)
    std::string oui = bssid.substr(0, 8);
    
    // Common vendor OUIs
    if (oui.substr(0, 8) == "00:1A:11" || oui.substr(0, 8) == "00:1A:11") {
        return "Google";
    } else if (oui.substr(0, 8) == "00:1B:63" || oui.substr(0, 8) == "00:1B:63") {
        return "Apple";
    } else if (oui.substr(0, 8) == "00:1C:C0" || oui.substr(0, 8) == "00:1C:C0") {
        return "Cisco";
    } else if (oui.substr(0, 8) == "00:1D:7E" || oui.substr(0, 8) == "00:1D:7E") {
        return "Netgear";
    } else if (oui.substr(0, 8) == "00:1E:40" || oui.substr(0, 8) == "00:1E:40") {
        return "Asus";
    } else if (oui.substr(0, 8) == "00:1F:3A" || oui.substr(0, 8) == "00:1F:3A") {
        return "Dell";
    } else if (oui.substr(0, 8) == "00:1F:3B" || oui.substr(0, 8) == "00:1F:3B") {
        return "HP";
    }
    
    return "Unknown";
}

int WindowsWifiScanner::estimateChannelWidth(const PWLAN_BSS_ENTRY pBssEntry) const {
    // Estimate based on frequency and capabilities
    if (pBssEntry->uChCenterFreq >= 5000) {
        // 5GHz - likely wider channels
        return 80; // Most 5GHz networks use 80MHz
    } else {
        // 2.4GHz - usually 20MHz or 40MHz
        return 20;
    }
}

bool WindowsWifiScanner::checkForPMF(const PWLAN_AVAILABLE_NETWORK pNetwork) const {
    // Check if PMF is supported (this would require parsing IE data)
    // For now, return false as it's not easily detectable via WlanAPI
    return false;
}

bool WindowsWifiScanner::checkForOWE(const PWLAN_AVAILABLE_NETWORK pNetwork) const {
    // Check if OWE is supported
    return false;
}

bool WindowsWifiScanner::checkForWPS(const PWLAN_AVAILABLE_NETWORK pNetwork) const {
    // Most consumer routers support WPS
    return true;
}

int WindowsWifiScanner::estimateDataRate(int frequency, int channelWidth) const {
    if (frequency >= 6000) {
        return channelWidth * 8; // 6GHz - Wi-Fi 6E
    } else if (frequency >= 5000) {
        return channelWidth * 6; // 5GHz - Wi-Fi 5/6
    } else {
        return channelWidth * 4; // 2.4GHz - Wi-Fi 4
    }
}

bool WindowsWifiScanner::detectRogueAP(const NetworkInfo& current, const std::vector<NetworkInfo>& existing) const {
    // Check for potential rogue APs
    for (const auto& network : existing) {
        // Same SSID but different BSSID (evil twin attack)
        if (network.ssid == current.ssid && network.bssid != current.bssid) {
            return true;
        }
        
        // Very similar SSID (typo squatting)
        if (isSimilarSSID(network.ssid, current.ssid)) {
            return true;
        }
    }
    
    return false;
}

bool WindowsWifiScanner::isSimilarSSID(const std::string& ssid1, const std::string& ssid2) const {
    if (ssid1.length() != ssid2.length()) return false;
    
    int differences = 0;
    for (size_t i = 0; i < ssid1.length(); i++) {
        if (ssid1[i] != ssid2[i]) differences++;
        if (differences > 1) return false; // Allow only 1 character difference
    }
    
    return differences == 1;
}

} // namespace WifiScanner
