#include "CommandProcessor.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>

namespace WifiScanner {

const std::string CommandProcessor::PROMPT = "wifi-cli> ";

CommandProcessor::CommandProcessor() {
    scanner_ = createWifiScanner();
    currentPage_ = 0;
}

void CommandProcessor::run() {
    std::string input;
    
    while (true) {
        std::cout << PROMPT;
        std::getline(std::cin, input);
        
        if (std::cin.eof()) {
            std::cout << std::endl;
            break;
        }
        
        if (!processCommand(input)) {
            break;
        }
    }
}

bool CommandProcessor::processCommand(const std::string& input) {
    if (input.empty()) {
        return true;
    }
    
    auto args = parseCommand(input);
    if (args.empty()) {
        return true;
    }
    
    std::string command = args[0];
    std::transform(command.begin(), command.end(), command.begin(), ::tolower);
    
    if (command == "scan" || command == "s") {
        return handleScanCommand(args);
    } else if (command == "dscan" || command == "ds") {
        return handleDeepScanCommand(args);
    } else if (command == "page" || command == "p") {
        return handlePageCommand(args);
    } else if (command == "help" || command == "h" || command == "?") {
        return handleHelpCommand(args);
    } else if (command == "version" || command == "v") {
        return handleVersionCommand(args);
    } else if (command == "exit" || command == "quit" || command == "q") {
        return handleExitCommand(args);
    } else {
        std::cout << "Unknown command: " << command << std::endl;
        std::cout << "Type 'help' for available commands" << std::endl;
        return true;
    }
}

bool CommandProcessor::handleScanCommand(const std::vector<std::string>& args) {
    std::cout << "Scanning for Wi-Fi networks..." << std::endl;
    
    if (!scanner_ || !scanner_->isSupported()) {
        std::cout << "Wi-Fi scanning is not supported on this platform." << std::endl;
        return true;
    }
    
    try {
        auto networks = scanner_->scan();
        if (networks.empty()) {
            std::cout << "No networks found." << std::endl;
        } else {
            std::cout << "Found " << networks.size() << " network(s):" << std::endl;
            std::cout << std::endl;
            
            // Grade and sort networks by security
            lastScanResults_ = grader_.gradeAndSortNetworks(networks);
            currentPage_ = 0;
            displayNetworks(lastScanResults_, currentPage_);
        }
    } catch (const std::exception& e) {
        std::cout << "Error during scan: " << e.what() << std::endl;
    }
    
    return true;
}

bool CommandProcessor::handleHelpCommand(const std::vector<std::string>& args) {
    showHelp();
    return true;
}

bool CommandProcessor::handleVersionCommand(const std::vector<std::string>& args) {
    showVersion();
    return true;
}

bool CommandProcessor::handleExitCommand(const std::vector<std::string>& args) {
    std::cout << "Goodbye!" << std::endl;
    return false;
}

bool CommandProcessor::handlePageCommand(const std::vector<std::string>& args) {
    if (lastScanResults_.empty()) {
        std::cout << "No scan results available. Run 'scan' first." << std::endl;
        return true;
    }
    
    size_t totalPages = (lastScanResults_.size() + NETWORKS_PER_PAGE - 1) / NETWORKS_PER_PAGE;
    
    if (args.size() > 1) {
        try {
            size_t requestedPage = std::stoul(args[1]) - 1; // Convert to 0-based index
            if (requestedPage < totalPages) {
                currentPage_ = requestedPage;
            } else {
                std::cout << "Page " << (requestedPage + 1) << " does not exist. ";
                std::cout << "Total pages: " << totalPages << std::endl;
                return true;
            }
        } catch (const std::exception& e) {
            std::cout << "Invalid page number. Use: page <number>" << std::endl;
            return true;
        }
    } else {
        // No page specified, show next page
        currentPage_ = (currentPage_ + 1) % totalPages;
    }
    
    displayNetworks(lastScanResults_, currentPage_);
    return true;
}

bool CommandProcessor::handleDeepScanCommand(const std::vector<std::string>& args) {
    if (lastScanResults_.empty()) {
        std::cout << "No scan results available. Run 'scan' first." << std::endl;
        return true;
    }
    
    if (args.size() < 2) {
        std::cout << "Usage: dscan <network_number> [test_type]" << std::endl;
        std::cout << "  network_number: Index of network to analyze (0-" << (lastScanResults_.size() - 1) << ")" << std::endl;
        std::cout << "  test_type: security, performance, threats, or all (default: all)" << std::endl;
        std::cout << std::endl;
        std::cout << "Examples:" << std::endl;
        std::cout << "  dscan 0          - Deep scan of first network" << std::endl;
        std::cout << "  dscan 5 security - Security analysis of 6th network" << std::endl;
        std::cout << "  ds 2 threats     - Threat analysis of 3rd network" << std::endl;
        return true;
    }
    
    try {
        size_t networkIndex = std::stoul(args[1]);
        if (networkIndex >= lastScanResults_.size()) {
            std::cout << "Network " << networkIndex << " does not exist. ";
            std::cout << "Available networks: 0-" << (lastScanResults_.size() - 1) << std::endl;
            return true;
        }
        
        const NetworkInfo& network = lastScanResults_[networkIndex];
        std::string testType = (args.size() > 2) ? args[2] : "all";
        
        std::cout << "🔍 Deep Scanning Network " << networkIndex << "..." << std::endl;
        std::cout << "==========================================" << std::endl;
        
        if (testType == "all" || testType == "security") {
            performSecurityAnalysis(network);
        }
        
        if (testType == "all" || testType == "performance") {
            performPerformanceAnalysis(network);
        }
        
        if (testType == "all" || testType == "threats") {
            performThreatAnalysis(network);
        }
        
        if (testType == "all") {
            performVulnerabilityAssessment(network);
        }
        
    } catch (const std::exception& e) {
        std::cout << "Error during deep scan: " << e.what() << std::endl;
    }
    
    return true;
}

void CommandProcessor::showHelp() const {
    std::cout << "Available commands:" << std::endl;
    std::cout << "  scan, s     - Scan for nearby Wi-Fi networks" << std::endl;
    std::cout << "  dscan, ds   - Deep scan specific network for detailed analysis" << std::endl;
    std::cout << "  page, p     - Navigate through scan results (page <number>)" << std::endl;
    std::cout << "  help, h, ?  - Show this help message" << std::endl;
    std::cout << "  version, v  - Show version information" << std::endl;
    std::cout << "  exit, quit, q - Exit the application" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << PROMPT << "scan" << std::endl;
    std::cout << "  " << PROMPT << "dscan 0" << std::endl;
    std::cout << "  " << PROMPT << "ds 5 security" << std::endl;
    std::cout << "  " << PROMPT << "page 2" << std::endl;
}

void CommandProcessor::showVersion() const {
    std::cout << "Wi-Fi Scanner v1.0.0" << std::endl;
    if (scanner_) {
        std::cout << "Platform: " << scanner_->getPlatformName() << std::endl;
    }
}

std::vector<std::string> CommandProcessor::parseCommand(const std::string& input) const {
    std::vector<std::string> args;
    std::istringstream iss(input);
    std::string arg;
    
    while (iss >> arg) {
        args.push_back(arg);
    }
    
    return args;
}

void CommandProcessor::displayNetworks(const std::vector<NetworkInfo>& networks, size_t page) const {
    if (networks.empty()) {
        std::cout << "No networks to display." << std::endl;
        return;
    }
    
    size_t totalPages = (networks.size() + NETWORKS_PER_PAGE - 1) / NETWORKS_PER_PAGE;
    size_t startIndex = page * NETWORKS_PER_PAGE;
    size_t endIndex = std::min(startIndex + NETWORKS_PER_PAGE, networks.size());
    
    std::cout << std::left << std::setw(20) << "SSID" 
              << std::setw(18) << "BSSID"
              << std::setw(15) << "Security"
              << std::setw(10) << "Grade"
              << std::setw(8) << "Signal"
              << std::setw(8) << "Channel"
              << std::endl;
    
    std::cout << std::string(80, '-') << std::endl;
    
    for (size_t i = startIndex; i < endIndex; ++i) {
        const auto& network = networks[i];
        std::cout << std::left << std::setw(20) << network.ssid.substr(0, 19)
                  << std::setw(18) << network.bssid.substr(0, 17)
                  << std::setw(15) << SecurityGrader::securityTypeToString(network.securityType).substr(0, 14)
                  << std::setw(10) << SecurityGrader::gradeToString(grader_.gradeNetwork(network)).substr(0, 9)
                  << std::setw(8) << network.signalStrength
                  << std::setw(8) << network.channel
                  << std::endl;
    }
    
    showPageNavigation(page, totalPages);
}

void CommandProcessor::displayNetworkDetails(const NetworkInfo& network) const {
    std::cout << "Network Details:" << std::endl;
    std::cout << "  SSID: " << network.ssid << std::endl;
    std::cout << "  BSSID: " << network.bssid << std::endl;
    std::cout << "  Security: " << SecurityGrader::securityTypeToString(network.securityType) << std::endl;
    std::cout << "  Grade: " << SecurityGrader::gradeToString(grader_.gradeNetwork(network)) << std::endl;
    std::cout << "  Signal Strength: " << network.signalStrength << " dBm" << std::endl;
    std::cout << "  Channel: " << network.channel << std::endl;
    std::cout << "  Frequency: " << network.frequency << " MHz" << std::endl;
    std::cout << "  Hidden: " << (network.isHidden ? "Yes" : "No") << std::endl;
    if (!network.capabilities.empty()) {
        std::cout << "  Capabilities: " << network.capabilities << std::endl;
    }
}

void CommandProcessor::showPageNavigation(size_t currentPage, size_t totalPages) const {
    std::cout << std::endl;
    std::cout << "Page " << (currentPage + 1) << " of " << totalPages << std::endl;
    std::cout << "Navigation: ";
    
    if (totalPages > 1) {
        if (currentPage > 0) {
            std::cout << "page " << currentPage << " (prev) | ";
        }
        if (currentPage < totalPages - 1) {
            std::cout << "page " << (currentPage + 2) << " (next) | ";
        }
        std::cout << "page <number> to jump to specific page";
    }
    
    std::cout << std::endl;
}

void CommandProcessor::performSecurityAnalysis(const NetworkInfo& network) const {
    std::cout << "🔒 SECURITY ANALYSIS" << std::endl;
    std::cout << "===================" << std::endl;
    
    // Basic security info
    std::cout << "Protocol: " << SecurityGrader::securityTypeToString(network.securityType) << std::endl;
    std::cout << "Grade: " << SecurityGrader::gradeToString(grader_.gradeNetwork(network)) << std::endl;
    std::cout << "Score: " << grader_.getCachedScore(network) << "/100" << std::endl;
    
    // Security features
    std::cout << "Features:" << std::endl;
    std::cout << "  PMF (Protected Management Frames): " << (network.supportsPMF ? "✅ Yes" : "❌ No") << std::endl;
    std::cout << "  OWE (Opportunistic Wireless Encryption): " << (network.supportsOWE ? "✅ Yes" : "❌ No") << std::endl;
    std::cout << "  WPS (Wi-Fi Protected Setup): " << (network.supportsWPS ? "⚠️  Yes (Security Risk)" : "✅ No") << std::endl;
    std::cout << "  Enterprise Authentication: " << (network.isEnterprise ? "✅ Yes" : "❌ No") << std::endl;
    
    // Channel analysis
    std::cout << "Channel Analysis:" << std::endl;
    std::cout << "  Frequency: " << network.frequency << " MHz" << std::endl;
    std::cout << "  Channel Width: " << network.channelWidth << " MHz" << std::endl;
    std::cout << "  Band: " << (network.frequency > 5000 ? "5/6 GHz" : "2.4 GHz") << std::endl;
    
    std::cout << std::endl;
}

void CommandProcessor::performPerformanceAnalysis(const NetworkInfo& network) const {
    std::cout << "⚡ PERFORMANCE ANALYSIS" << std::endl;
    std::cout << "=======================" << std::endl;
    
    // Signal analysis
    std::cout << "Signal Quality:" << std::endl;
    std::cout << "  RSSI: " << network.signalStrength << " dBm" << std::endl;
    
    if (network.signalStrength >= -50) {
        std::cout << "  Status: 🟢 Excellent (Very close to router)" << std::endl;
    } else if (network.signalStrength >= -60) {
        std::cout << "  Status: 🟡 Good (Close to router)" << std::endl;
    } else if (network.signalStrength >= -70) {
        std::cout << "  Status: 🟠 Fair (Moderate distance)" << std::endl;
    } else if (network.signalStrength >= -80) {
        std::cout << "  Status: 🔴 Poor (Far from router)" << std::endl;
    } else {
        std::cout << "  Status: ⚫ Very Poor (Very far or obstructed)" << std::endl;
    }
    
    // Data rate analysis
    if (network.maxDataRate > 0) {
        std::cout << "Data Rate: " << network.maxDataRate << " Mbps" << std::endl;
    }
    
    // Channel congestion analysis
    std::cout << "Channel Congestion:" << std::endl;
    if (network.frequency >= 2400 && network.frequency <= 2500) {
        std::cout << "  ⚠️  2.4 GHz band (High congestion, slower speeds)" << std::endl;
    } else if (network.frequency >= 5000 && network.frequency <= 6000) {
        std::cout << "  ✅ 5 GHz band (Low congestion, faster speeds)" << std::endl;
    } else if (network.frequency >= 6000) {
        std::cout << "  🚀 6 GHz band (Ultra-low congestion, fastest speeds)" << std::endl;
    }
    
    std::cout << std::endl;
}

void CommandProcessor::performThreatAnalysis(const NetworkInfo& network) const {
    std::cout << "⚠️  THREAT ANALYSIS" << std::endl;
    std::cout << "==================" << std::endl;
    
    // Threat detection
    std::cout << "Threat Indicators:" << std::endl;
    std::cout << "  Rogue AP: " << (network.isRogueAP ? "🚨 DETECTED" : "✅ None detected") << std::endl;
    std::cout << "  Evil Twin: " << (network.isEvilTwin ? "🚨 DETECTED" : "✅ None detected") << std::endl;
    std::cout << "  Typo Squatting: " << (network.isTypoSquatting ? "🚨 DETECTED" : "✅ None detected") << std::endl;
    std::cout << "  Anomalous Behavior: " << (network.hasAnomalousBehavior ? "🚨 DETECTED" : "✅ None detected") << std::endl;
    
    // Security risks
    std::cout << "Security Risks:" << std::endl;
    if (network.securityType == SecurityType::OPEN) {
        std::cout << "  🚨 OPEN NETWORK - No encryption, extremely vulnerable" << std::endl;
    } else if (network.securityType == SecurityType::WEP) {
        std::cout << "  🚨 WEP - Broken encryption, easily crackable" << std::endl;
    } else if (network.securityType == SecurityType::WPA) {
        std::cout << "  ⚠️  WPA - Weak encryption, vulnerable to attacks" << std::endl;
    } else if (network.supportsWPS) {
        std::cout << "  ⚠️  WPS enabled - Potential brute force vulnerability" << std::endl;
    }
    
    // Vendor analysis
    if (!network.vendor.empty() && network.vendor != "Unknown") {
        std::cout << "Vendor: " << network.vendor << std::endl;
    }
    
    std::cout << std::endl;
}

void CommandProcessor::performVulnerabilityAssessment(const NetworkInfo& network) const {
    std::cout << "🔍 VULNERABILITY ASSESSMENT" << std::endl;
    std::cout << "==========================" << std::endl;
    
    int score = grader_.getCachedScore(network);
    
    // Overall risk assessment
    std::cout << "Risk Level: ";
    if (score >= 70) {
        std::cout << "🟢 LOW RISK" << std::endl;
    } else if (score >= 40) {
        std::cout << "🟡 MEDIUM RISK" << std::endl;
    } else if (score >= 20) {
        std::cout << "🟠 HIGH RISK" << std::endl;
    } else {
        std::cout << "🔴 CRITICAL RISK" << std::endl;
    }
    
    // Recommendations
    std::cout << "Recommendations:" << std::endl;
    if (network.securityType == SecurityType::OPEN) {
        std::cout << "  🚨 NEVER connect to this network" << std::endl;
        std::cout << "  🚨 All traffic is visible to anyone nearby" << std::endl;
    } else if (network.securityType == SecurityType::WEP) {
        std::cout << "  🚨 Avoid this network - encryption is broken" << std::endl;
    } else if (network.supportsWPS) {
        std::cout << "  ⚠️  Consider disabling WPS on your router" << std::endl;
    } else if (network.frequency < 5000) {
        std::cout << "  💡 2.4 GHz networks are slower and more congested" << std::endl;
    }
    
    if (network.isEnterprise) {
        std::cout << "  ✅ Enterprise networks are generally more secure" << std::endl;
    }
    
    std::cout << std::endl;
}

} // namespace WifiScanner
