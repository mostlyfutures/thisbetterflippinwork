#ifdef __APPLE__
#include "platforms/MacWifiScanner.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <regex>

// CoreWLAN framework headers
#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>

namespace WifiScanner {

MacWifiScanner::MacWifiScanner() {
    // Constructor - nothing special needed for CoreWLAN
}

MacWifiScanner::~MacWifiScanner() {
    // Destructor - CoreWLAN handles cleanup automatically
}

std::vector<NetworkInfo> MacWifiScanner::scan() {
    std::vector<NetworkInfo> networks;
    
    @try {
        @autoreleasepool {
            // Get the default Wi-Fi interface using the modern API
            CWWiFiClient* wifiClient = [CWWiFiClient sharedWiFiClient];
            CWInterface* wifi = [wifiClient interface];
            
            if (!wifi) {
                std::cerr << "No Wi-Fi interface found" << std::endl;
                return networks;
            }
            
            // Scan for networks
            NSError* error = nil;
            NSSet* scanResults = [wifi scanForNetworksWithSSID:nil error:&error];
            
            if (error) {
                std::cerr << "Error scanning for networks: " << [[error localizedDescription] UTF8String] << std::endl;
                return networks;
            }
        
        // Process scan results
        for (CWNetwork* network in scanResults) {
            NetworkInfo info;
            
            // SSID - try multiple CoreWLAN API methods
            NSString* ssid = nil;
            if ([network respondsToSelector:@selector(ssid)]) {
                ssid = [network ssid];
            } else if ([network respondsToSelector:@selector(ssidBeacon)]) {
                ssid = [network ssidBeacon];
            } else if ([network respondsToSelector:@selector(valueForKey:)]) {
                ssid = [network valueForKey:@"ssid"];
            }
            
            if (ssid && ![ssid isEqualToString:@""]) {
                info.ssid = [ssid UTF8String];
                // Detect guest networks based on SSID patterns
                info.isGuestNetwork = detectGuestNetwork([ssid UTF8String]);
            } else {
                info.ssid = "Hidden Network";
            }
            
            // BSSID (MAC address) - use the correct API method
            NSString* bssid = [network valueForKey:@"bssid"];
            if (bssid) {
                info.bssid = [bssid UTF8String];
                // Extract vendor from BSSID (first 6 characters)
                info.vendor = extractVendorFromBSSID([bssid UTF8String]);
            } else {
                info.bssid = "Unknown";
            }
            
            // Security type - use the correct API
            // Note: CoreWLAN API has changed, using securityType property
            id security = [network valueForKey:@"securityType"];
            if (security) {
                info.securityType = parseSecurityTypeFromCoreWLAN((int)[security integerValue]);
            } else {
                info.securityType = SecurityType::UNKNOWN;
            }
            
            // Determine if enterprise based on security type
            info.isEnterprise = (info.securityType == SecurityType::WPA2_ENTERPRISE || 
                                info.securityType == SecurityType::WPA3_ENTERPRISE);
            
            // Signal strength (RSSI) - use the correct method
            NSInteger rssi = [network rssiValue];
            info.signalStrength = (int)rssi;
            
            // Channel - use the correct method
            CWChannel* wlanChannel = [network wlanChannel];
            if (wlanChannel) {
                NSInteger channelNumber = [wlanChannel channelNumber];
                if (channelNumber > 0) {
                    info.channel = (int)channelNumber;
                }
            }
            
            // Frequency (calculate from channel)
            if (info.channel > 0) {
                info.frequency = channelToFrequency(info.channel);
            }
            
            // Channel width (estimate based on capabilities)
            info.channelWidth = estimateChannelWidth(nullptr);
            
            // Hidden network - check if network is hidden
            BOOL isHidden = NO; // Default to not hidden
            @try {
                // Try to access hidden property if available
                if ([network respondsToSelector:@selector(isHidden)]) {
                    isHidden = [network isHidden];
                }
            } @catch (...) {
                // Property not available, keep default
            }
            info.isHidden = isHidden;
            
            // Capabilities - simplified for now
            std::stringstream ss;
            if (security) {
                ss << "Security:" << [security integerValue];
            } else {
                ss << "Security:Unknown";
            }
            info.capabilities = ss.str();
            
            // Check for security features
            info.supportsPMF = checkForPMF(nullptr);
            info.supportsOWE = checkForOWE(nullptr);
            
            // WPS support (common on consumer routers)
            info.supportsWPS = true; // Most consumer routers support WPS
            
            // Estimate data rate based on capabilities and frequency
            info.maxDataRate = estimateDataRate(info.frequency, info.channelWidth);
            
            networks.push_back(info);
        }
        } // Close @autoreleasepool
    } @catch (NSException* exception) {
        std::cerr << "CoreWLAN exception: " << [[exception reason] UTF8String] << std::endl;
    } @catch (...) {
        std::cerr << "Unknown Objective-C exception in CoreWLAN" << std::endl;
    }
    
    return networks;
}

bool MacWifiScanner::isSupported() const {
    // CoreWLAN is available on macOS 10.6+
    return true;
}

std::string MacWifiScanner::getPlatformName() const {
    return "macOS";
}

SecurityType MacWifiScanner::parseSecurityType(const std::string& securityString) const {
    // This method is not used in the CoreWLAN implementation
    // The actual parsing is done in parseSecurityTypeFromCoreWLAN
    return SecurityType::UNKNOWN;
}

SecurityType MacWifiScanner::parseSecurityTypeFromCoreWLAN(int security) const {
    switch (security) {
        case kCWSecurityNone:
            return SecurityType::OPEN;
        case kCWSecurityWEP:
            return SecurityType::WEP;
        case kCWSecurityWPAPersonal:
            return SecurityType::WPA;
        case kCWSecurityWPA2Personal:
            return SecurityType::WPA2_PERSONAL;
        case kCWSecurityWPA2Enterprise:
            return SecurityType::WPA2_ENTERPRISE;
        case kCWSecurityWPAPersonalMixed:
            return SecurityType::WPA;
        case kCWSecurityWPA3Personal:
            return SecurityType::WPA3_PERSONAL;
        case kCWSecurityWPA3Enterprise:
            return SecurityType::WPA3_ENTERPRISE;
        default:
            return SecurityType::UNKNOWN;
    }
}

int MacWifiScanner::parseSignalStrength(int rssi) const {
    // RSSI is already in dBm on macOS
    return rssi;
}

int MacWifiScanner::frequencyToChannel(int frequency) const {
    // Convert frequency to channel number
    if (frequency >= 2412 && frequency <= 2484) {
        // 2.4 GHz band
        return (frequency - 2412) / 5 + 1;
    } else if (frequency >= 5170 && frequency <= 5825) {
        // 5 GHz band
        return (frequency - 5170) / 5 + 34;
    }
    return 0;
}

int MacWifiScanner::channelToFrequency(int channel) const {
    // Convert channel number to frequency
    if (channel >= 1 && channel <= 13) {
        // 2.4 GHz band
        return 2407 + (channel * 5);
    } else if (channel >= 34 && channel <= 165) {
        // 5 GHz band
        return 5000 + (channel * 5);
    }
    return 0;
}

bool MacWifiScanner::detectGuestNetwork(const std::string& ssid) const {
    std::string lowerSSID = ssid;
    std::transform(lowerSSID.begin(), lowerSSID.end(), lowerSSID.begin(), ::tolower);
    
    // Common guest network patterns
    std::vector<std::string> guestPatterns = {
        "guest", "visitor", "public", "hotel", "cafe", "restaurant",
        "airport", "mall", "library", "university", "college",
        "temporary", "temp", "test", "demo"
    };
    
    for (const auto& pattern : guestPatterns) {
        if (lowerSSID.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

std::string MacWifiScanner::extractVendorFromBSSID(const std::string& bssid) const {
    if (bssid.length() < 8) return "";
    
    // Extract first 6 characters (OUI - Organizationally Unique Identifier)
    std::string oui = bssid.substr(0, 8);
    
    // Common vendor OUIs (simplified - in a real app you'd use a database)
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
    }
    
    return "Unknown";
}

int MacWifiScanner::estimateChannelWidth(const void* capabilities) const {
    // Estimate channel width based on capabilities
    // This is a simplified estimation - real implementation would parse actual capabilities
    return 20; // Default to 20MHz for now
}

bool MacWifiScanner::checkForPMF(const void* capabilities) const {
    // Check if Protected Management Frames are supported
    // This would require parsing the actual capability bits
    // For now, return false as it's not easily detectable via CoreWLAN
    return false;
}

bool MacWifiScanner::checkForOWE(const void* capabilities) const {
    // Check if Opportunistic Wireless Encryption is supported
    // This would require parsing the actual capability bits
    // For now, return false as it's not easily detectable via CoreWLAN
    return false;
}

int MacWifiScanner::estimateDataRate(int frequency, int channelWidth) const {
    // Estimate maximum data rate based on frequency and channel width
    if (frequency >= 6000) {
        // 6GHz band - Wi-Fi 6E
        return channelWidth * 8; // Rough estimate
    } else if (frequency >= 5000) {
        // 5GHz band - Wi-Fi 5/6
        return channelWidth * 6; // Rough estimate
    } else {
        // 2.4GHz band - Wi-Fi 4
        return channelWidth * 4; // Rough estimate
    }
}

} // namespace WifiScanner

#else
#error "CoreWLAN is not supported on non-macOS platforms."
#endif
