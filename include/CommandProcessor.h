#pragma once

#include "WifiScanner.h"
#include "SecurityGrader.h"
#include <string>
#include <vector>
#include <memory>

namespace WifiScanner {

class CommandProcessor {
public:
    CommandProcessor();
    ~CommandProcessor() = default;
    
    // Main command processing loop
    void run();
    
    // Process a single command
    bool processCommand(const std::string& input);
    
    // Display help information
    void showHelp() const;
    
    // Display version information
    void showVersion() const;
    
private:
    std::unique_ptr<WifiScanner> scanner_;
    SecurityGrader grader_;
    std::vector<NetworkInfo> lastScanResults_;
    size_t currentPage_;
    static const size_t NETWORKS_PER_PAGE = 10;
    
    // Command handlers
    bool handleScanCommand(const std::vector<std::string>& args);
    bool handleDeepScanCommand(const std::vector<std::string>& args);
    bool handleHelpCommand(const std::vector<std::string>& args);
    bool handleVersionCommand(const std::vector<std::string>& args);
    bool handleExitCommand(const std::vector<std::string>& args);
    bool handlePageCommand(const std::vector<std::string>& args);
    
    // Utility functions
    std::vector<std::string> parseCommand(const std::string& input) const;
    void displayNetworks(const std::vector<NetworkInfo>& networks, size_t page = 0) const;
    void displayNetworkDetails(const NetworkInfo& network) const;
    void showPageNavigation(size_t currentPage, size_t totalPages) const;
    
    // Deep scan analysis methods
    void performSecurityAnalysis(const NetworkInfo& network) const;
    void performPerformanceAnalysis(const NetworkInfo& network) const;
    void performThreatAnalysis(const NetworkInfo& network) const;
    void performVulnerabilityAssessment(const NetworkInfo& network) const;
    
    // Command prompt
    static const std::string PROMPT;
};

} // namespace WifiScanner
