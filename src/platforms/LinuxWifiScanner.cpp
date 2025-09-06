#include "platforms/LinuxWifiScanner.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <regex>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <fstream>
#include <algorithm>

namespace WifiScanner {

LinuxWifiScanner::LinuxWifiScanner() {
    // Constructor - check for required tools
}

LinuxWifiScanner::~LinuxWifiScanner() {
    // Destructor
}

std::vector<NetworkInfo> LinuxWifiScanner::scan() {
    std::vector<NetworkInfo> networks;
    
    // Try NetworkManager first (more reliable)
    networks = scanUsingNetworkManager();
    
    // If NetworkManager fails, fall back to iw command
    if (networks.empty()) {
        networks = scanUsingIw();
    }
    
    // If both fail, try scanning /proc/net/wireless
    if (networks.empty()) {
        networks = scanUsingProcNet();
    }
    
    return networks;
}

bool LinuxWifiScanner::isSupported() const {
    // Check if we have any of the required tools
    return (system("which nmcli >/dev/null 2>&1") == 0) ||
           (system("which iw >/dev/null 2>&1") == 0) ||
           (system("which iwlist >/dev/null 2>&1") == 0);
}

std::string LinuxWifiScanner::getPlatformName() const {
    return "Linux";
}

SecurityType LinuxWifiScanner::parseSecurityType(const std::string& securityString) const {
    std::string lower = securityString;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower.find("wpa3") != std::string::npos) {
        if (lower.find("enterprise") != std::string::npos) {
            return SecurityType::WPA3_ENTERPRISE;
        }
        return SecurityType::WPA3_PERSONAL;
    } else if (lower.find("wpa2") != std::string::npos) {
        if (lower.find("enterprise") != std::string::npos) {
            return SecurityType::WPA2_ENTERPRISE;
        }
        return SecurityType::WPA2_PERSONAL;
    } else if (lower.find("wpa") != std::string::npos) {
        return SecurityType::WPA;
    } else if (lower.find("wep") != std::string::npos) {
        return SecurityType::WEP;
    } else if (lower.find("open") != std::string::npos || lower.find("none") != std::string::npos) {
        return SecurityType::OPEN;
    }
    
    return SecurityType::UNKNOWN;
}

int LinuxWifiScanner::parseSignalStrength(int rssi) const {
    return rssi;
}

int LinuxWifiScanner::frequencyToChannel(int frequency) const {
    if (frequency >= 2412 && frequency <= 2484) {
        return (frequency - 2412) / 5 + 1;
    } else if (frequency >= 5170 && frequency <= 5825) {
        return (frequency - 5170) / 5 + 34;
    }
    return 0;
}

int LinuxWifiScanner::frequencyToChannel(int frequency) const {
    if (frequency >= 2412 && frequency <= 2484) {
        return (frequency - 2412) / 5 + 1;
    } else if (frequency >= 5170 && frequency <= 5825) {
        return (frequency - 5170) / 5 + 34;
    }
    return 0;
}

std::vector<NetworkInfo> LinuxWifiScanner::scanUsingIw() const {
    std::vector<NetworkInfo> networks;
    
    // Use 'iw dev' to get interface names
    std::string cmd = "iw dev | grep Interface | awk '{print $2}'";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return networks;
    
    char buffer[128];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }
    pclose(pipe);
    
    // Parse interfaces and scan each one
    std::istringstream iss(result);
    std::string interface;
    while (std::getline(iss, interface)) {
        // Remove newline
        interface.erase(std::remove(interface.begin(), interface.end(), '\n'), interface.end());
        if (interface.empty()) continue;
        
        // Scan this interface
        auto interfaceNetworks = scanInterfaceWithIw(interface);
        networks.insert(networks.end(), interfaceNetworks.begin(), interfaceNetworks.end());
    }
    
    return networks;
}

std::vector<NetworkInfo> LinuxWifiScanner::scanInterfaceWithIw(const std::string& interface) const {
    std::vector<NetworkInfo> networks;
    
    // Use 'iw dev <interface> scan' to get networks
    std::string cmd = "iw dev " + interface + " scan | grep -E 'SSID|BSS|freq|signal|capabilities'";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return networks;
    
    char buffer[512];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }
    pclose(pipe);
    
    // Parse the scan results
    networks = parseIwScanOutput(result);
    
    return networks;
}

std::vector<NetworkInfo> LinuxWifiScanner::parseIwScanOutput(const std::string& output) const {
    std::vector<NetworkInfo> networks;
    std::istringstream iss(output);
    std::string line;
    
    NetworkInfo current;
    bool hasBSS = false;
    
    while (std::getline(iss, line)) {
        if (line.find("BSS ") != std::string::npos) {
            // Save previous network if we have one
            if (hasBSS && !current.ssid.empty()) {
                // Fill in missing fields
                if (current.frequency > 0) {
                    current.channel = frequencyToChannel(current.frequency);
                }
                current.isGuestNetwork = detectGuestNetwork(current.ssid);
                current.vendor = extractVendorFromBSSID(current.bssid);
                current.channelWidth = estimateChannelWidth(current.frequency);
                current.supportsPMF = checkForPMF(current.capabilities);
                current.supportsOWE = checkForOWE(current.capabilities);
                current.supportsWPS = checkForWPS(current.capabilities);
                current.maxDataRate = estimateDataRate(current.frequency, current.channelWidth);
                
                networks.push_back(current);
            }
            
            // Start new network
            current = NetworkInfo();
            hasBSS = true;
            
            // Parse BSSID
            std::regex bssRegex(R"(BSS ([0-9a-fA-F:]+))");
            std::smatch match;
            if (std::regex_search(line, match, bssRegex)) {
                current.bssid = match[1].str();
            }
        } else if (line.find("SSID: ") != std::string::npos) {
            std::regex ssidRegex(R"(SSID: (.+))");
            std::smatch match;
            if (std::regex_search(line, match, ssidRegex)) {
                current.ssid = match[1].str();
            }
        } else if (line.find("freq: ") != std::string::npos) {
            std::regex freqRegex(R"(freq: (\d+))");
            std::smatch match;
            if (std::regex_search(line, match, freqRegex)) {
                current.frequency = std::stoi(match[1].str());
            }
        } else if (line.find("signal: ") != std::string::npos) {
            std::regex signalRegex(R"(signal: (-\d+))");
            std::smatch match;
            if (std::regex_search(line, match, signalRegex)) {
                current.signalStrength = std::stoi(match[1].str());
            }
        } else if (line.find("capabilities: ") != std::string::npos) {
            std::regex capRegex(R"(capabilities: (.+))");
            std::smatch match;
            if (std::regex_search(line, match, capRegex)) {
                current.capabilities = match[1].str();
            }
        }
    }
    
    // Don't forget the last network
    if (hasBSS && !current.ssid.empty()) {
        if (current.frequency > 0) {
            current.channel = frequencyToChannel(current.frequency);
        }
        current.isGuestNetwork = detectGuestNetwork(current.ssid);
        current.vendor = extractVendorFromBSSID(current.bssid);
        current.channelWidth = estimateChannelWidth(current.frequency);
        current.supportsPMF = checkForPMF(current.capabilities);
        current.supportsOWE = checkForOWE(current.capabilities);
        current.supportsWPS = checkForWPS(current.capabilities);
        current.maxDataRate = estimateDataRate(current.frequency, current.channelWidth);
        
        networks.push_back(current);
    }
    
    return networks;
}

std::vector<NetworkInfo> LinuxWifiScanner::scanUsingNetworkManager() const {
    std::vector<NetworkInfo> networks;
    
    // Use 'nmcli device wifi list' to get networks
    std::string cmd = "nmcli -t -f SSID,BSSID,CHAN,RATE,SIGNAL,SECURITY device wifi list";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return networks;
    
    char buffer[512];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }
    pclose(pipe);
    
    // Parse NetworkManager output
    networks = parseNmcliOutput(result);
    
    return networks;
}

std::vector<NetworkInfo> LinuxWifiScanner::parseNmcliOutput(const std::string& output) const {
    std::vector<NetworkInfo> networks;
    std::istringstream iss(output);
    std::string line;
    
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        
        NetworkInfo info;
        std::vector<std::string> fields;
        std::stringstream ss(line);
        std::string field;
        
        // Split by colon (nmcli uses colon as separator)
        while (std::getline(ss, field, ':')) {
            fields.push_back(field);
        }
        
        if (fields.size() >= 6) {
            info.ssid = fields[0];
            info.bssid = fields[1];
            
            if (!fields[2].empty()) {
                info.channel = std::stoi(fields[2]);
                info.frequency = channelToFrequency(info.channel);
            }
            
            if (!fields[3].empty()) {
                // Parse rate (e.g., "54 Mbit/s")
                std::regex rateRegex(R"((\d+))");
                std::smatch match;
                if (std::regex_search(fields[3], match, rateRegex)) {
                    info.maxDataRate = std::stoi(match[1].str());
                }
            }
            
            if (!fields[4].empty()) {
                info.signalStrength = std::stoi(fields[4]);
            }
            
            info.securityType = parseSecurityType(fields[5]);
            info.isEnterprise = (info.securityType == SecurityType::WPA2_ENTERPRISE || 
                               info.securityType == SecurityType::WPA3_ENTERPRISE);
            
            // Fill in additional fields
            info.isGuestNetwork = detectGuestNetwork(info.ssid);
            info.vendor = extractVendorFromBSSID(info.bssid);
            info.channelWidth = estimateChannelWidth(info.frequency);
            info.supportsPMF = checkForPMF(info.capabilities);
            info.supportsOWE = checkForOWE(info.capabilities);
            info.supportsWPS = checkForWPS(info.capabilities);
            
            networks.push_back(info);
        }
    }
    
    return networks;
}

std::vector<NetworkInfo> LinuxWifiScanner::scanUsingProcNet() const {
    std::vector<NetworkInfo> networks;
    
    // Read /proc/net/wireless for basic information
    std::ifstream file("/proc/net/wireless");
    if (!file.is_open()) return networks;
    
    std::string line;
    // Skip header lines
    std::getline(file, line); // Inter-| sta-|   Quality        |   Discarded packets
    std::getline(file, line); //  face | tus | link level noise |  nwid  crypt   frag
    
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        
        NetworkInfo info;
        std::istringstream iss(line);
        std::string interface, status, link, level, noise, nwid, crypt, frag;
        
        iss >> interface >> status >> link >> level >> noise >> nwid >> crypt >> frag;
        
        if (interface != "Inter-") {
            // Parse signal level (remove dBm suffix)
            if (!level.empty() && level != "0") {
                info.signalStrength = std::stoi(level);
            }
            
            // Try to get SSID from interface name or other sources
            info.ssid = "Unknown_" + interface;
            
            networks.push_back(info);
        }
    }
    
    return networks;
}

bool LinuxWifiScanner::detectGuestNetwork(const std::string& ssid) const {
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

std::string LinuxWifiScanner::extractVendorFromBSSID(const std::string& bssid) const {
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

int LinuxWifiScanner::estimateChannelWidth(int frequency) const {
    if (frequency >= 5000) {
        return 80; // 5GHz networks usually use 80MHz
    } else {
        return 20; // 2.4GHz networks usually use 20MHz
    }
}

bool LinuxWifiScanner::checkForPMF(const std::string& capabilities) const {
    if (capabilities.empty()) return false;
    
    std::string lower = capabilities;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    return (lower.find("pmf") != std::string::npos ||
            lower.find("protected") != std::string::npos);
}

bool LinuxWifiScanner::checkForOWE(const std::string& capabilities) const {
    if (capabilities.empty()) return false;
    
    std::string lower = capabilities;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    return (lower.find("owe") != std::string::npos ||
            lower.find("opportunistic") != std::string::npos);
}

bool LinuxWifiScanner::checkForWPS(const std::string& capabilities) const {
    if (capabilities.empty()) return false;
    
    std::string lower = capabilities;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    return (lower.find("wps") != std::string::npos);
}

int LinuxWifiScanner::estimateDataRate(int frequency, int channelWidth) const {
    if (frequency >= 6000) {
        return channelWidth * 8; // 6GHz - Wi-Fi 6E
    } else if (frequency >= 5000) {
        return channelWidth * 6; // 5GHz - Wi-Fi 5/6
    } else {
        return channelWidth * 4; // 2.4GHz - Wi-Fi 4
    }
}

} // namespace WifiScanner
