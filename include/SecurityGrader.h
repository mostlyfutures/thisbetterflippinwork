#pragma once

#include "NetworkInfo.h"
#include <string>
#include <vector>
#include <unordered_map>

namespace WifiScanner {

class SecurityGrader {
public:
    SecurityGrader();
    ~SecurityGrader() = default;
    
    // Grade a single network
    SecurityGrade gradeNetwork(const NetworkInfo& network) const;
    
    // Grade multiple networks and return sorted by security
    std::vector<NetworkInfo> gradeAndSortNetworks(const std::vector<NetworkInfo>& networks) const;
    
    // Get security grade as string
    static std::string gradeToString(SecurityGrade grade);
    
    // Get security type as string
    static std::string securityTypeToString(SecurityType type);
    
    // Performance optimization methods
    int getCachedScore(const NetworkInfo& network) const;
    void clearCache() const;
    
private:
    // Calculate numerical score for security grading
    int calculateSecurityScore(const NetworkInfo& network) const;
    
    // Individual scoring components
    int calculateEncryptionScore(SecurityType securityType) const;
    int calculateAuthenticationScore(const NetworkInfo& network) const;
    int calculateChannelScore(const NetworkInfo& network) const;
    int calculateFeatureScore(const NetworkInfo& network) const;
    int calculateConfigurationScore(const NetworkInfo& network) const;
    int calculateVendorScore(const NetworkInfo& network) const;
    int calculateAdvancedSecurityScore(const NetworkInfo& network) const;
    
    // Performance optimization: Score caching
    mutable std::unordered_map<std::string, int> scoreCache_;
};

} // namespace WifiScanner
