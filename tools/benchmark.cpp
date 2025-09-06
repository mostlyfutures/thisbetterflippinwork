#include "../include/SecurityGrader.h"
#include "../include/NetworkInfo.h"
#include <iostream>
#include <chrono>
#include <random>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>

using namespace WifiScanner;

// Generate random networks for testing
std::vector<NetworkInfo> generateRandomNetworks(size_t count) {
    std::vector<NetworkInfo> networks;
    std::random_device rd;
    std::mt19937 gen(rd());
    
    std::vector<SecurityType> securityTypes = {
        SecurityType::OPEN, SecurityType::WEP, SecurityType::WPA,
        SecurityType::WPA2_PERSONAL, SecurityType::WPA2_ENTERPRISE,
        SecurityType::WPA3_PERSONAL, SecurityType::WPA3_ENTERPRISE
    };
    
    std::vector<std::string> vendors = {
        "Cisco", "Aruba", "Netgear", "Asus", "TP-Link", "D-Link", "Linksys"
    };
    
    std::vector<std::string> ssidPrefixes = {
        "Network", "WiFi", "Home", "Office", "Guest", "Public", "Corporate"
    };
    
    for (size_t i = 0; i < count; ++i) {
        NetworkInfo network;
        
        // Random SSID
        std::uniform_int_distribution<> prefixDist(0, ssidPrefixes.size() - 1);
        std::uniform_int_distribution<> numDist(100, 999);
        network.ssid = ssidPrefixes[prefixDist(gen)] + std::to_string(numDist(gen));
        
        // Random BSSID
        std::uniform_int_distribution<> hexDist(0, 255);
        std::stringstream bssid;
        for (int k = 0; k < 6; k++) {
            if (k > 0) bssid << ":";
            bssid << std::hex << std::setw(2) << std::setfill('0') << hexDist(gen);
        }
        network.bssid = bssid.str();
        
        // Random security type
        std::uniform_int_distribution<> secDist(0, securityTypes.size() - 1);
        network.securityType = securityTypes[secDist(gen)];
        
        // Random frequency
        std::uniform_int_distribution<> freqDist(0, 2);
        switch (freqDist(gen)) {
            case 0: network.frequency = 2412 + (gen() % 13) * 5; break; // 2.4GHz
            case 1: network.frequency = 5170 + (gen() % 25) * 5; break; // 5GHz
            case 2: network.frequency = 5955 + (gen() % 15) * 5; break; // 6GHz
        }
        
        // Random channel width
        std::uniform_int_distribution<> widthDist(0, 3);
        std::vector<int> widths = {20, 40, 80, 160};
        network.channelWidth = widths[widthDist(gen)];
        
        // Random signal strength
        std::uniform_int_distribution<> signalDist(-90, -30);
        network.signalStrength = signalDist(gen);
        
        // Random channel
        if (network.frequency >= 2400 && network.frequency <= 2484) {
            network.channel = (network.frequency - 2412) / 5 + 1;
        } else if (network.frequency >= 5000) {
            network.channel = (network.frequency - 5170) / 5 + 34;
        }
        
        // Random vendor
        std::uniform_int_distribution<> vendorDist(0, vendors.size() - 1);
        network.vendor = vendors[vendorDist(gen)];
        
        // Random features
        network.isEnterprise = (gen() % 4 == 0); // 25% enterprise
        network.supportsPMF = (gen() % 3 == 0);  // 33% PMF
        network.supportsOWE = (gen() % 5 == 0);  // 20% OWE
        network.supportsWPS = (gen() % 2 == 0);  // 50% WPS
        network.isHidden = (gen() % 10 == 0);    // 10% hidden
        network.isGuestNetwork = (gen() % 6 == 0); // 17% guest
        
        // Random advanced features
        network.isRogueAP = (gen() % 20 == 0);      // 5% rogue
        network.isEvilTwin = (gen() % 50 == 0);     // 2% evil twin
        network.isTypoSquatting = (gen() % 100 == 0); // 1% typo squatting
        network.beaconInterval = 100 + (gen() % 200); // 100-300ms
        network.respondsToProbes = (gen() % 8 == 0);  // 12.5% suspicious
        network.hasAnomalousBehavior = (gen() % 15 == 0); // 6.7% anomalous
        
        // Random data rate
        network.maxDataRate = network.channelWidth * (5 + (gen() % 10));
        
        networks.push_back(network);
    }
    
    return networks;
}

// Benchmark security grading performance
void benchmarkSecurityGrading(size_t networkCount) {
    std::cout << "\n=== Security Grading Performance Benchmark ===" << std::endl;
    std::cout << "Testing with " << networkCount << " networks..." << std::endl;
    
    // Generate test networks
    auto startGen = std::chrono::high_resolution_clock::now();
    auto networks = generateRandomNetworks(networkCount);
    auto endGen = std::chrono::high_resolution_clock::now();
    auto genDuration = std::chrono::duration_cast<std::chrono::microseconds>(endGen - startGen);
    std::cout << "Generated " << networkCount << " networks in " << genDuration.count() << " μs" << std::endl;
    
    SecurityGrader grader;
    
    // Benchmark individual network grading
    auto startIndividual = std::chrono::high_resolution_clock::now();
    for (const auto& network : networks) {
        grader.gradeNetwork(network);
    }
    auto endIndividual = std::chrono::high_resolution_clock::now();
    auto individualDuration = std::chrono::duration_cast<std::chrono::microseconds>(endIndividual - startIndividual);
    
    std::cout << "Individual grading: " << individualDuration.count() << " μs total, "
              << individualDuration.count() / networkCount << " μs per network" << std::endl;
    
    // Benchmark bulk grading and sorting
    auto startBulk = std::chrono::high_resolution_clock::now();
    auto sorted = grader.gradeAndSortNetworks(networks);
    auto endBulk = std::chrono::high_resolution_clock::now();
    auto bulkDuration = std::chrono::duration_cast<std::chrono::microseconds>(endBulk - startBulk);
    
    std::cout << "Bulk grading + sorting: " << bulkDuration.count() << " μs total, "
              << bulkDuration.count() / networkCount << " μs per network" << std::endl;
    
    // Benchmark with caching
    grader.clearCache();
    auto startCached = std::chrono::high_resolution_clock::now();
    for (const auto& network : networks) {
        grader.getCachedScore(network);
    }
    auto endCached = std::chrono::high_resolution_clock::now();
    auto cachedDuration = std::chrono::duration_cast<std::chrono::microseconds>(endCached - startCached);
    
    std::cout << "Cached scoring: " << cachedDuration.count() << " μs total, "
              << cachedDuration.count() / networkCount << " μs per network" << std::endl;
    
    // Performance improvements
    double individualImprovement = (double)individualDuration.count() / cachedDuration.count();
    double bulkImprovement = (double)bulkDuration.count() / cachedDuration.count();
    
    std::cout << "\nPerformance Improvements:" << std::endl;
    std::cout << "Caching vs Individual: " << std::fixed << std::setprecision(2) 
              << individualImprovement << "x faster" << std::endl;
    std::cout << "Caching vs Bulk: " << std::fixed << std::setprecision(2) 
              << bulkImprovement << "x faster" << std::endl;
}

// Benchmark memory usage
void benchmarkMemoryUsage(size_t networkCount) {
    std::cout << "\n=== Memory Usage Benchmark ===" << std::endl;
    
    auto networks = generateRandomNetworks(networkCount);
    
    // Estimate memory usage
    size_t estimatedSize = networks.size() * sizeof(NetworkInfo);
    size_t estimatedStringSize = 0;
    
    for (const auto& network : networks) {
        estimatedStringSize += network.ssid.capacity() + network.bssid.capacity() + 
                              network.capabilities.capacity() + network.vendor.capacity();
    }
    
    std::cout << "Network count: " << networkCount << std::endl;
    std::cout << "Estimated struct memory: " << estimatedSize / 1024 << " KB" << std::endl;
    std::cout << "Estimated string memory: " << estimatedStringSize / 1024 << " KB" << std::endl;
    std::cout << "Total estimated memory: " << (estimatedSize + estimatedStringSize) / 1024 << " KB" << std::endl;
    std::cout << "Memory per network: " << (estimatedSize + estimatedStringSize) / networkCount << " bytes" << std::endl;
}

// Benchmark different network sizes
void benchmarkScalability() {
    std::cout << "\n=== Scalability Benchmark ===" << std::endl;
    
    std::vector<size_t> sizes = {100, 500, 1000, 5000, 10000};
    
    for (size_t size : sizes) {
        std::cout << "\n--- Testing " << size << " networks ---" << std::endl;
        benchmarkSecurityGrading(size);
        benchmarkMemoryUsage(size);
    }
}

// Benchmark specific security features
void benchmarkSecurityFeatures() {
    std::cout << "\n=== Security Features Benchmark ===" << std::endl;
    
    // Test networks with different security configurations
    std::vector<NetworkInfo> testNetworks;
    
    // WPA3 Enterprise with all features
    NetworkInfo wpa3Enterprise;
    wpa3Enterprise.securityType = SecurityType::WPA3_ENTERPRISE;
    wpa3Enterprise.isEnterprise = true;
    wpa3Enterprise.supportsPMF = true;
    wpa3Enterprise.supportsOWE = true;
    wpa3Enterprise.supportsWPS = false;
    wpa3Enterprise.frequency = 5955;
    wpa3Enterprise.channelWidth = 160;
    wpa3Enterprise.vendor = "Cisco";
    testNetworks.push_back(wpa3Enterprise);
    
    // Open network with suspicious behavior
    NetworkInfo suspiciousOpen;
    suspiciousOpen.securityType = SecurityType::OPEN;
    suspiciousOpen.isRogueAP = true;
    suspiciousOpen.isEvilTwin = true;
    suspiciousOpen.beaconInterval = 25;
    suspiciousOpen.respondsToProbes = true;
    suspiciousOpen.hasAnomalousBehavior = true;
    testNetworks.push_back(suspiciousOpen);
    
    // WPA2 Personal with mixed features
    NetworkInfo wpa2Mixed;
    wpa2Mixed.securityType = SecurityType::WPA2_PERSONAL;
    wpa2Mixed.supportsPMF = true;
    wpa2Mixed.supportsWPS = true;
    wpa2Mixed.frequency = 2412;
    wpa2Mixed.channelWidth = 20;
    wpa2Mixed.vendor = "Netgear";
    testNetworks.push_back(wpa2Mixed);
    
    SecurityGrader grader;
    
    for (size_t i = 0; i < testNetworks.size(); ++i) {
        const auto& network = testNetworks[i];
        auto grade = grader.gradeNetwork(network);
        auto score = grader.getCachedScore(network);
        
        std::cout << "Network " << (i + 1) << ":" << std::endl;
        std::cout << "  Security: " << SecurityGrader::securityTypeToString(network.securityType) << std::endl;
        std::cout << "  Grade: " << SecurityGrader::gradeToString(grade) << std::endl;
        std::cout << "  Score: " << score << "/100" << std::endl;
        std::cout << "  Features: PMF=" << network.supportsPMF 
                  << ", OWE=" << network.supportsOWE 
                  << ", WPS=" << network.supportsWPS << std::endl;
        std::cout << "  Threats: Rogue=" << network.isRogueAP 
                  << ", EvilTwin=" << network.isEvilTwin 
                  << ", Anomalous=" << network.hasAnomalousBehavior << std::endl;
        std::cout << std::endl;
    }
}

int main() {
    std::cout << "🚀 Wi-Fi Scanner Performance Benchmark Tool" << std::endl;
    std::cout << "==========================================" << std::endl;
    
    try {
        // Run scalability benchmarks
        benchmarkScalability();
        
        // Run security feature benchmarks
        benchmarkSecurityFeatures();
        
        std::cout << "\n✅ All benchmarks completed successfully!" << std::endl;
        std::cout << "\nPerformance Summary:" << std::endl;
        std::cout << "- Individual network grading: Baseline performance" << std::endl;
        std::cout << "- Bulk grading + sorting: Optimized for multiple networks" << std::endl;
        std::cout << "- Cached scoring: Best performance for repeated calculations" << std::endl;
        std::cout << "- Memory usage: Efficient data structures" << std::endl;
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Benchmark failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "\n❌ Benchmark failed with unknown exception" << std::endl;
        return 1;
    }
}
