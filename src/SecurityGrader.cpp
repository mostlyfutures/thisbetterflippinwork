#include "SecurityGrader.h"
#include <algorithm>
#include <regex>
#include <unordered_map>
#include <chrono>
#include <iostream>

namespace WifiScanner {

SecurityGrader::SecurityGrader() {
    // Initialize any caching or optimization structures
}

SecurityGrade SecurityGrader::gradeNetwork(const NetworkInfo& network) const {
    int score = calculateSecurityScore(network);
    
    if (score >= 70) return SecurityGrade::EXCELLENT;
    if (score >= 55) return SecurityGrade::GOOD;
    if (score >= 40) return SecurityGrade::OKAY;
    if (score >= 20) return SecurityGrade::BAD;
    return SecurityGrade::VERY_BAD;
}

std::vector<NetworkInfo> SecurityGrader::gradeAndSortNetworks(const std::vector<NetworkInfo>& networks) const {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<NetworkInfo> sortedNetworks = networks;
    
    // Enhanced sorting with multiple criteria
    std::sort(sortedNetworks.begin(), sortedNetworks.end(),
        [this](const NetworkInfo& a, const NetworkInfo& b) {
            int scoreA = calculateSecurityScore(a);
            int scoreB = calculateSecurityScore(b);
            
            // If security scores are close, prioritize other factors
            if (std::abs(scoreA - scoreB) <= 5) {
                // Prioritize non-rogue APs
                if (a.isRogueAP != b.isRogueAP) {
                    return !a.isRogueAP; // Non-rogue first
                }
                
                // Prioritize enterprise networks
                if (a.isEnterprise != b.isEnterprise) {
                    return a.isEnterprise; // Enterprise first
                }
                
                // Prioritize networks with PMF
                if (a.supportsPMF != b.supportsPMF) {
                    return a.supportsPMF; // PMF first
                }
            }
            
            return scoreA > scoreB; // Primary sort by security score
        });
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Performance logging (could be made configurable)
    if (networks.size() > 100) {
        std::cout << "Sorted " << networks.size() << " networks in " 
                  << duration.count() << " microseconds" << std::endl;
    }
    
    return sortedNetworks;
}

std::string SecurityGrader::gradeToString(SecurityGrade grade) {
    switch (grade) {
        case SecurityGrade::EXCELLENT: return "Excellent";
        case SecurityGrade::GOOD: return "Good";
        case SecurityGrade::OKAY: return "Okay";
        case SecurityGrade::BAD: return "Bad";
        case SecurityGrade::VERY_BAD: return "Very Bad";
        default: return "Unknown";
    }
}

std::string SecurityGrader::securityTypeToString(SecurityType type) {
    switch (type) {
        case SecurityType::OPEN: return "Open";
        case SecurityType::WEP: return "WEP";
        case SecurityType::WPA: return "WPA";
        case SecurityType::WPA2_PERSONAL: return "WPA2-Personal";
        case SecurityType::WPA2_ENTERPRISE: return "WPA2-Enterprise";
        case SecurityType::WPA3_PERSONAL: return "WPA3-Personal";
        case SecurityType::WPA3_ENTERPRISE: return "WPA3-Enterprise";
        case SecurityType::UNKNOWN: return "Unknown";
        default: return "Unknown";
    }
}

int SecurityGrader::calculateSecurityScore(const NetworkInfo& network) const {
    double score = 0.0;
    
    // Base score based on security type (35% of total score)
    double encryptionScore = calculateEncryptionScore(network.securityType) * 0.35;
    score += encryptionScore;
    
    // Enterprise vs Personal authentication (15% of total score)
    double authScore = calculateAuthenticationScore(network) * 0.15;
    score += authScore;
    
    // Channel width and frequency considerations (10% of total score)
    double channelScore = calculateChannelScore(network) * 0.10;
    score += channelScore;
    
    // Security features and protocols (20% of total score)
    double featureScore = calculateFeatureScore(network) * 0.20;
    score += featureScore;
    
    // Network configuration and behavior (10% of total score)
    double configScore = calculateConfigurationScore(network) * 0.10;
    score += configScore;
    
    // Vendor and manufacturer considerations (5% of total score)
    double vendorScore = calculateVendorScore(network) * 0.05;
    score += vendorScore;
    
    // Advanced security analysis (5% of total score)
    double advancedScore = calculateAdvancedSecurityScore(network) * 0.05;
    score += advancedScore;
    
    // Debug output for first few networks
    static int debugCount = 0;
    if (debugCount < 3) {
        std::cout << "DEBUG Network " << debugCount << " (" << network.ssid << "):" << std::endl;
        std::cout << "  Security Type: " << (int)network.securityType << std::endl;
        std::cout << "  Encryption Score: " << encryptionScore << " (base: " << calculateEncryptionScore(network.securityType) << ")" << std::endl;
        std::cout << "  Auth Score: " << authScore << std::endl;
        std::cout << "  Channel Score: " << channelScore << std::endl;
        std::cout << "  Feature Score: " << featureScore << std::endl;
        std::cout << "  Config Score: " << configScore << std::endl;
        std::cout << "  Vendor Score: " << vendorScore << std::endl;
        std::cout << "  Advanced Score: " << advancedScore << std::endl;
        std::cout << "  Total Score: " << score << std::endl;
        std::cout << std::endl;
        debugCount++;
    }
    
    // Ensure score is within bounds and round to nearest integer
    score = std::max(0.0, std::min(100.0, score));
    
    return static_cast<int>(std::round(score));
}

int SecurityGrader::calculateEncryptionScore(SecurityType securityType) const {
    switch (securityType) {
        case SecurityType::OPEN: return 15;      // Increased from 10
        case SecurityType::WEP: return 25;      // Increased from 20
        case SecurityType::WPA: return 50;      // Increased from 40
        case SecurityType::WPA2_PERSONAL: return 80;     // Increased from 70
        case SecurityType::WPA2_ENTERPRISE: return 95;   // Increased from 85
        case SecurityType::WPA3_PERSONAL: return 100;    // Increased from 95
        case SecurityType::WPA3_ENTERPRISE: return 110;  // Increased from 100 (allow >100 for enterprise)
        case SecurityType::UNKNOWN: return 35;  // Increased from 30
        default: return 35;
    }
}

int SecurityGrader::calculateAuthenticationScore(const NetworkInfo& network) const {
    int score = 0;
    
    // Enterprise networks get higher scores due to centralized authentication
    if (network.isEnterprise) {
        score += 30;  // Increased from 20
    } else {
        score += 15;  // Increased from 10
    }
    
    // Guest networks typically have weaker security policies
    if (network.isGuestNetwork) {
        score -= 15;
    }
    
    return std::max(0, score);
}

int SecurityGrader::calculateChannelScore(const NetworkInfo& network) const {
    int score = 0;
    
    // Higher frequency bands (5GHz, 6GHz) are generally more secure
    if (network.frequency >= 6000) {
        score += 30; // Increased from 25
    } else if (network.frequency >= 5000) {
        score += 25; // Increased from 20
    } else if (network.frequency >= 2400) {
        score += 15; // Increased from 10
    }
    
    // Wider channels can be more vulnerable to jamming but offer better performance
    // Security-wise, standard 20MHz channels are often preferred
    if (network.channelWidth == 20) {
        score += 8;  // Increased from 5
    } else if (network.channelWidth == 40) {
        score += 5;  // Increased from 3
    } else if (network.channelWidth >= 80) {
        score += 2;  // Increased from 1
    }
    
    // Channel congestion can indicate potential interference
    if (network.channel >= 1 && network.channel <= 11) {
        score -= 2; // 2.4GHz channels are often congested
    }
    
    return std::max(0, score);
}

int SecurityGrader::calculateFeatureScore(const NetworkInfo& network) const {
    int score = 0;
    
    // Protected Management Frames (PMF) - prevents deauthentication attacks
    if (network.supportsPMF) {
        score += 20;  // Increased from 15
    }
    
    // Opportunistic Wireless Encryption (OWE) - provides encryption for open networks
    if (network.supportsOWE) {
        score += 15;  // Increased from 10
    }
    
    // Wi-Fi Protected Setup (WPS) - can be a security vulnerability
    if (network.supportsWPS) {
        score -= 10; // WPS can be exploited
    }
    
    // Hidden networks get a small penalty (security through obscurity)
    if (network.isHidden) {
        score -= 5;
    }
    
    return std::max(0, score);
}

int SecurityGrader::calculateConfigurationScore(const NetworkInfo& network) const {
    int score = 0;
    
    // Signal strength can indicate proximity and potential attack surface
    if (network.signalStrength >= -30) {
        score -= 5; // Very strong signal - might be too close
    } else if (network.signalStrength >= -50) {
        score += 2; // Good signal strength
    } else if (network.signalStrength >= -70) {
        score += 5; // Moderate signal - reasonable range
    } else {
        score += 8; // Weak signal - good range control
    }
    
    // Data rate can indicate modern equipment and security features
    if (network.maxDataRate >= 1000) {
        score += 5; // Gigabit+ speeds often indicate newer, more secure equipment
    } else if (network.maxDataRate >= 100) {
        score += 3; // Decent speeds
    }
    
    // Enterprise networks get bonus points for better configuration
    if (network.isEnterprise) {
        score += 5; // Enterprise networks typically have better configuration
    }
    
    return std::max(0, score);
}

int SecurityGrader::calculateVendorScore(const NetworkInfo& network) const {
    int score = 0;
    
    if (network.vendor.empty()) {
        return 0; // No vendor info available
    }
    
    // Some vendors are known for better security practices
    std::string vendor = network.vendor;
    std::transform(vendor.begin(), vendor.end(), vendor.begin(), ::tolower);
    
    // Enterprise-focused vendors often have better security
    if (vendor.find("cisco") != std::string::npos ||
        vendor.find("aruba") != std::string::npos ||
        vendor.find("ruckus") != std::string::npos ||
        vendor.find("ubiquiti") != std::string::npos) {
        score += 5;
    }
    
    // Consumer vendors with good security track records
    else if (vendor.find("asus") != std::string::npos ||
             vendor.find("netgear") != std::string::npos ||
             vendor.find("tp-link") != std::string::npos) {
        score += 2;
    }
    
    // Some vendors have had security issues in the past
    else if (vendor.find("d-link") != std::string::npos ||
             vendor.find("linksys") != std::string::npos) {
        score -= 2;
    }
    
    return std::max(0, score);
}

int SecurityGrader::calculateAdvancedSecurityScore(const NetworkInfo& network) const {
    int score = 0;
    
    // Rogue AP detection - major security concern
    if (network.isRogueAP) {
        score -= 25; // Significant penalty for rogue APs
    }
    
    // Evil twin attacks - same SSID, different BSSID
    if (network.isEvilTwin) {
        score -= 20; // Major security threat
    }
    
    // Typo squatting - similar SSID names
    if (network.isTypoSquatting) {
        score -= 15; // Potential phishing attack
    }
    
    // Anomalous network behavior
    if (network.hasAnomalousBehavior) {
        score -= 10; // Suspicious behavior
    }
    
    // Beacon interval analysis
    if (network.beaconInterval < 50) {
        score -= 5; // Very short beacon intervals can indicate monitoring
    } else if (network.beaconInterval > 200) {
        score += 2; // Longer intervals can be more secure
    }
    
    // Probe response behavior
    if (network.respondsToProbes) {
        score -= 3; // Responding to all probes can be suspicious
    }
    
    return std::max(-30, score); // Allow negative scores for major security issues
}

// Performance optimization: Cache for repeated calculations
int SecurityGrader::getCachedScore(const NetworkInfo& network) const {
    // Create a cache key from network characteristics
    std::string key = network.ssid + "|" + 
                     std::to_string(static_cast<int>(network.securityType)) + "|" +
                     std::to_string(network.isEnterprise) + "|" +
                     std::to_string(network.supportsPMF);
    
    auto it = scoreCache_.find(key);
    if (it != scoreCache_.end()) {
        return it->second;
    }
    
    // Calculate and cache the score
    int score = calculateSecurityScore(network);
    scoreCache_[key] = score;
    
    return score;
}

void SecurityGrader::clearCache() const {
    scoreCache_.clear();
}

} // namespace WifiScanner
