#include "SecurityGrader.h"
#include <iostream>
#include <cassert>
#include <vector>

using namespace WifiScanner;

// Test helper function
void assertGrade(const NetworkInfo& network, SecurityGrade expectedGrade, const std::string& testName) {
    SecurityGrader grader;
    SecurityGrade actualGrade = grader.gradeNetwork(network);
    
    if (actualGrade == expectedGrade) {
        std::cout << "✓ " << testName << " - PASSED" << std::endl;
    } else {
        std::cout << "✗ " << testName << " - FAILED (Expected: " 
                  << SecurityGrader::gradeToString(expectedGrade) 
                  << ", Got: " << SecurityGrader::gradeToString(actualGrade) << ")" << std::endl;
        assert(false);
    }
}

// Test helper function for score ranges
void assertScoreRange(const NetworkInfo& network, int minScore, int maxScore, const std::string& testName) {
    SecurityGrader grader;
    int score = grader.getCachedScore(network);
    
    if (score >= minScore && score <= maxScore) {
        std::cout << "✓ " << testName << " - PASSED (Score: " << score << ")" << std::endl;
    } else {
        std::cout << "✗ " << testName << " - FAILED (Score: " << score 
                  << " not in range [" << minScore << ", " << maxScore << "])" << std::endl;
        assert(false);
    }
}

void testBasicEncryptionGrading() {
    std::cout << "\n=== Testing Basic Encryption Grading ===" << std::endl;
    
    NetworkInfo network;
    
    // Test WPA3-Enterprise
    network.securityType = SecurityType::WPA3_ENTERPRISE;
    network.isEnterprise = true;  // Set enterprise flag
    network.frequency = 5955;     // 6GHz band for better score
    network.channelWidth = 160;   // Wide channel
    network.supportsPMF = true;   // Protected Management Frames
    network.supportsOWE = true;   // Opportunistic Wireless Encryption
    network.supportsWPS = false;  // No WPS for enterprise
    network.vendor = "Cisco";     // Enterprise vendor
    network.signalStrength = -60; // Good signal strength
    network.maxDataRate = 1200;   // Gigabit+ data rate
    assertGrade(network, SecurityGrade::GOOD, "WPA3-Enterprise should be Good (realistic enterprise security)");
    
    // Test WPA3-Personal
    network.securityType = SecurityType::WPA3_PERSONAL;
    network.isEnterprise = false; // Personal network
    network.frequency = 5180;     // 5GHz band
    network.channelWidth = 80;    // Standard wide channel
    network.supportsPMF = true;   // PMF support
    network.supportsOWE = true;   // OWE support
    network.supportsWPS = false;  // No WPS
    network.vendor = "Netgear";   // Consumer vendor
    assertGrade(network, SecurityGrade::GOOD, "WPA3-Personal should be Good (strong protocol, consumer config)");
    
    // Test WPA2-Enterprise
    network.securityType = SecurityType::WPA2_ENTERPRISE;
    network.isEnterprise = true;  // Enterprise network
    network.frequency = 5180;     // 5GHz band
    network.channelWidth = 80;    // Wide channel
    network.supportsPMF = true;   // PMF support
    network.supportsOWE = false;  // No OWE (WPA2)
    network.supportsWPS = false;  // No WPS for enterprise
    network.vendor = "Cisco";     // Enterprise vendor
    assertGrade(network, SecurityGrade::OKAY, "WPA2-Enterprise should be Okay (strong protocol, enterprise config)");
    
    // Test WPA2-Personal
    network.securityType = SecurityType::WPA2_PERSONAL;
    network.isEnterprise = false; // Personal network
    network.frequency = 2412;     // 2.4GHz band
    network.channelWidth = 20;    // Standard channel
    network.supportsPMF = false;  // No PMF
    network.supportsOWE = false;  // No OWE
    network.supportsWPS = true;   // WPS support (common)
    network.vendor = "Netgear";   // Consumer vendor
    assertGrade(network, SecurityGrade::OKAY, "WPA2-Personal should be Okay");
    
    // Test WPA
    network.securityType = SecurityType::WPA;
    network.isEnterprise = false; // Personal network
    network.frequency = 2412;     // 2.4GHz band
    network.channelWidth = 20;    // Standard channel
    network.supportsPMF = false;  // No PMF
    network.supportsOWE = false;  // No OWE
    network.supportsWPS = true;   // WPS support
    network.vendor = "Linksys";   // Consumer vendor
    assertGrade(network, SecurityGrade::BAD, "WPA should be Bad");
    
    // Test WEP
    network.securityType = SecurityType::WEP;
    network.isEnterprise = false; // Personal network
    network.frequency = 2412;     // 2.4GHz band
    network.channelWidth = 20;    // Standard channel
    network.supportsPMF = false;  // No PMF
    network.supportsOWE = false;  // No OWE
    network.supportsWPS = false;  // No WPS
    network.vendor = "D-Link";    // Consumer vendor
    assertGrade(network, SecurityGrade::VERY_BAD, "WEP should be Very Bad");
    
    // Test Open
    network.securityType = SecurityType::OPEN;
    network.isEnterprise = false; // Personal network
    network.frequency = 2412;     // 2.4GHz band
    network.channelWidth = 20;    // Standard channel
    network.supportsPMF = false;  // No PMF
    network.supportsOWE = false;  // No OWE
    network.supportsWPS = false;  // No WPS
    network.vendor = "Unknown";   // Unknown vendor
    assertGrade(network, SecurityGrade::VERY_BAD, "Open should be Very Bad");
}

void testEnterpriseVsPersonal() {
    std::cout << "\n=== Testing Enterprise vs Personal Authentication ===" << std::endl;
    
    NetworkInfo personal, enterprise;
    personal.securityType = SecurityType::WPA2_PERSONAL;
    personal.isEnterprise = false;
    enterprise.securityType = SecurityType::WPA2_PERSONAL;
    enterprise.isEnterprise = true;
    
    SecurityGrader grader;
    int personalScore = grader.getCachedScore(personal);
    int enterpriseScore = grader.getCachedScore(enterprise);
    
    if (enterpriseScore > personalScore) {
        std::cout << "✓ Enterprise authentication should score higher - PASSED" << std::endl;
    } else {
        std::cout << "✗ Enterprise authentication should score higher - FAILED" << std::endl;
        assert(false);
    }
}

void testGuestNetworkDetection() {
    std::cout << "\n=== Testing Guest Network Detection ===" << std::endl;
    
    NetworkInfo regular, guest;
    regular.securityType = SecurityType::WPA2_PERSONAL;
    regular.ssid = "MyHomeNetwork";
    regular.isGuestNetwork = false;
    
    guest.securityType = SecurityType::WPA2_PERSONAL;
    guest.ssid = "HotelGuestWiFi";
    guest.isGuestNetwork = true;
    
    SecurityGrader grader;
    int regularScore = grader.getCachedScore(regular);
    int guestScore = grader.getCachedScore(guest);
    
    if (regularScore > guestScore) {
        std::cout << "✓ Regular networks should score higher than guest networks - PASSED" << std::endl;
    } else {
        std::cout << "✗ Regular networks should score higher than guest networks - FAILED" << std::endl;
        assert(false);
    }
}

void testFrequencyBandScoring() {
    std::cout << "\n=== Testing Frequency Band Scoring ===" << std::endl;
    
    NetworkInfo network;
    network.securityType = SecurityType::WPA2_PERSONAL;
    
    // Test 2.4GHz
    network.frequency = 2412;
    int score24 = SecurityGrader().getCachedScore(network);
    
    // Test 5GHz
    network.frequency = 5180;
    int score5 = SecurityGrader().getCachedScore(network);
    
    // Test 6GHz
    network.frequency = 5955;
    int score6 = SecurityGrader().getCachedScore(network);
    
    if (score6 >= score5 && score5 >= score24) {
        std::cout << "✓ Higher frequency bands should score higher - PASSED" << std::endl;
    } else {
        std::cout << "✗ Higher frequency bands should score higher - FAILED" << std::endl;
        assert(false);
    }
}

void testSecurityFeatures() {
    std::cout << "\n=== Testing Security Features ===" << std::endl;
    
    NetworkInfo basic, withPMF, withOWE, withWPS;
    basic.securityType = SecurityType::WPA2_PERSONAL;
    
    withPMF = basic;
    withPMF.supportsPMF = true;
    
    withOWE = basic;
    withOWE.supportsOWE = true;
    
    withWPS = basic;
    withWPS.supportsWPS = true;
    
    SecurityGrader grader;
    int basicScore = grader.getCachedScore(basic);
    int pmfScore = grader.getCachedScore(withPMF);
    int oweScore = grader.getCachedScore(withOWE);
    int wpsScore = grader.getCachedScore(withWPS);
    
    if (pmfScore > basicScore) {
        std::cout << "✓ PMF should improve score - PASSED" << std::endl;
    } else {
        std::cout << "✗ PMF should improve score - FAILED" << std::endl;
        assert(false);
    }
    
    if (oweScore > basicScore) {
        std::cout << "✓ OWE should improve score - PASSED" << std::endl;
    } else {
        std::cout << "✗ OWE should improve score - FAILED" << std::endl;
        assert(false);
    }
    
    if (wpsScore < basicScore) {
        std::cout << "✓ WPS should decrease score - PASSED" << std::endl;
    } else {
        std::cout << "✗ WPS should decrease score - FAILED" << std::endl;
        assert(false);
    }
}

void testRogueAPDetection() {
    std::cout << "\n=== Testing Rogue AP Detection ===" << std::endl;
    
    NetworkInfo legitimate, rogue;
    legitimate.securityType = SecurityType::WPA2_PERSONAL;
    legitimate.isRogueAP = false;
    
    rogue.securityType = SecurityType::WPA2_PERSONAL;
    rogue.isRogueAP = true;
    
    SecurityGrader grader;
    int legitimateScore = grader.getCachedScore(legitimate);
    int rogueScore = grader.getCachedScore(rogue);
    
    if (legitimateScore > rogueScore) {
        std::cout << "✓ Legitimate APs should score higher than rogue APs - PASSED" << std::endl;
    } else {
        std::cout << "✗ Legitimate APs should score higher than rogue APs - FAILED" << std::endl;
        assert(false);
    }
}

void testVendorScoring() {
    std::cout << "\n=== Testing Vendor Scoring ===" << std::endl;
    
    NetworkInfo network;
    network.securityType = SecurityType::WPA2_PERSONAL;
    
    // Test enterprise vendor
    network.vendor = "Cisco";
    int ciscoScore = SecurityGrader().getCachedScore(network);
    
    // Test consumer vendor
    network.vendor = "Asus";
    int asusScore = SecurityGrader().getCachedScore(network);
    
    // Test vendor with issues
    network.vendor = "D-Link";
    int dlinkScore = SecurityGrader().getCachedScore(network);
    
    if (ciscoScore >= asusScore && asusScore >= dlinkScore) {
        std::cout << "✓ Vendor reputation should affect scoring - PASSED" << std::endl;
    } else {
        std::cout << "✗ Vendor reputation should affect scoring - FAILED" << std::endl;
        assert(false);
    }
}

void testPerformanceOptimization() {
    std::cout << "\n=== Testing Performance Optimization ===" << std::endl;
    
    SecurityGrader grader;
    
    // Create a network
    NetworkInfo network;
    network.securityType = SecurityType::WPA2_PERSONAL;
    network.ssid = "TestNetwork";
    
    // First call should calculate score
    auto start1 = std::chrono::high_resolution_clock::now();
    int score1 = grader.getCachedScore(network);
    auto end1 = std::chrono::high_resolution_clock::now();
    auto duration1 = std::chrono::duration_cast<std::chrono::microseconds>(end1 - start1);
    
    // Second call should use cache
    auto start2 = std::chrono::high_resolution_clock::now();
    int score2 = grader.getCachedScore(network);
    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end2 - start2);
    
    if (score1 == score2 && duration2 < duration1) {
        std::cout << "✓ Caching should improve performance - PASSED" << std::endl;
    } else {
        std::cout << "✗ Caching should improve performance - FAILED" << std::endl;
        assert(false);
    }
}

void testNetworkSorting() {
    std::cout << "\n=== Testing Network Sorting ===" << std::endl;
    
    std::vector<NetworkInfo> networks;
    
    // Create networks with different security levels
    NetworkInfo open, wep, wpa2, wpa3;
    
    open.securityType = SecurityType::OPEN;
    open.ssid = "OpenNetwork";
    
    wep.securityType = SecurityType::WEP;
    wep.ssid = "WEPNetwork";
    
    wpa2.securityType = SecurityType::WPA2_PERSONAL;
    wpa2.ssid = "WPA2Network";
    
    wpa3.securityType = SecurityType::WPA3_PERSONAL;
    wpa3.ssid = "WPA3Network";
    
    networks = {open, wep, wpa2, wpa3};
    
    SecurityGrader grader;
    auto sorted = grader.gradeAndSortNetworks(networks);
    
    // Check that networks are sorted by security (highest first)
    if (sorted[0].securityType == SecurityType::WPA3_PERSONAL &&
        sorted[1].securityType == SecurityType::WPA2_PERSONAL &&
        sorted[2].securityType == SecurityType::WEP &&
        sorted[3].securityType == SecurityType::OPEN) {
        std::cout << "✓ Networks should be sorted by security level - PASSED" << std::endl;
    } else {
        std::cout << "✗ Networks should be sorted by security level - FAILED" << std::endl;
        assert(false);
    }
}

int main() {
    std::cout << "Starting SecurityGrader Tests..." << std::endl;
    
    try {
        testBasicEncryptionGrading();
        testEnterpriseVsPersonal();
        testGuestNetworkDetection();
        testFrequencyBandScoring();
        testSecurityFeatures();
        testRogueAPDetection();
        testVendorScoring();
        testPerformanceOptimization();
        testNetworkSorting();
        
        std::cout << "\n🎉 All tests passed! SecurityGrader is working correctly." << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "\n❌ Test failed with unknown exception" << std::endl;
        return 1;
    }
}
