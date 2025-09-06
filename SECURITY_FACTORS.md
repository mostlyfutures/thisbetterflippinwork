# Wi-Fi Network Security Factors

This document outlines all the factors considered when grading Wi-Fi network security, going beyond just encryption type to provide a comprehensive security assessment.

## 1. Encryption Type (40% of total score)

The foundation of Wi-Fi security, encryption type determines the base security level:

- **WPA3-Enterprise**: 100 points - Latest standard with enterprise authentication
- **WPA3-Personal**: 95 points - Latest standard for personal use
- **WPA2-Enterprise**: 85 points - Enterprise-grade with centralized authentication
- **WPA2-Personal**: 70 points - Widely adopted, generally secure
- **WPA**: 40 points - Older standard, some vulnerabilities
- **WEP**: 20 points - Completely broken, easily cracked
- **Open**: 10 points - No encryption, completely vulnerable

## 2. Authentication Method (15% of total score)

How users are authenticated to the network:

- **Enterprise Authentication**: +20 points
  - Uses RADIUS servers for centralized authentication
  - Individual user accounts with strong passwords
  - Better audit trails and access control
  
- **Personal Authentication**: +10 points
  - Shared password (PSK - Pre-Shared Key)
  - Vulnerable to password sharing and brute force attacks
  
- **Guest Networks**: -15 points
  - Often have weak or no passwords
  - Limited security policies
  - Common targets for attacks

## 3. Channel and Frequency (10% of total score)

Physical characteristics that affect security:

- **Frequency Band**:
  - 6GHz (Wi-Fi 6E): +25 points - Newest band, less congestion
  - 5GHz: +20 points - Less interference, better performance
  - 2.4GHz: +10 points - More congestion, interference
  
- **Channel Width**:
  - 20MHz: +5 points - Standard width, good security
  - 40MHz: +3 points - Wider channels, potential jamming vulnerability
  - 80MHz+: +1 point - Very wide, more vulnerable to jamming
  
- **Channel Congestion**:
  - 2.4GHz channels 1-11: -2 points - Often congested
  - 5GHz channels: +0 points - Generally less congested

## 4. Security Features and Protocols (20% of total score)

Advanced security capabilities:

- **Protected Management Frames (PMF)**: +15 points
  - Prevents deauthentication attacks
  - Protects against man-in-the-middle attacks
  - Required for WPA3, optional for WPA2
  
- **Opportunistic Wireless Encryption (OWE)**: +10 points
  - Provides encryption for open networks
  - Each client gets unique encryption key
  - Prevents passive eavesdropping
  
- **Wi-Fi Protected Setup (WPS)**: -10 points
  - Can be exploited to recover network password
  - PIN-based attacks are common
  - Should be disabled on production networks
  
- **Hidden Networks**: -5 points
  - Security through obscurity
  - Doesn't prevent active attacks
  - Can make legitimate connections harder

## 5. Network Configuration (10% of total score)

Operational security considerations:

- **Signal Strength**:
  - Very strong (-30 dBm or better): -5 points - Too close, large attack surface
  - Good (-30 to -50 dBm): +0 points - Appropriate coverage
  - Moderate (-50 to -70 dBm): +2 points - Reasonable range control
  - Weak (-70 dBm or worse): +5 points - Good range control
  
- **Data Rate**:
  - 1 Gbps+: +3 points - Modern equipment, better security features
  - 100 Mbps+: +1 point - Decent speeds
  - Below 100 Mbps: +0 points - Older equipment

## 6. Vendor and Manufacturer (5% of total score)

Manufacturer reputation and track record:

- **Enterprise Vendors** (+5 points):
  - Cisco, Aruba, Ruckus, Ubiquiti
  - Regular security updates
  - Enterprise-grade security features
  
- **Consumer Vendors - Good Track Record** (+2 points):
  - Asus, Netgear, TP-Link
  - Regular firmware updates
  - Good security practices
  
- **Consumer Vendors - Security Issues** (-2 points):
  - D-Link, Linksys
  - History of security vulnerabilities
  - Slower patch releases

## Additional Considerations (Not Currently Scored)

These factors could be added in future versions:

### Network Behavior
- **Beacon Interval**: Very short intervals can indicate monitoring
- **Probe Response**: Networks that respond to all probe requests
- **Rogue AP Detection**: Networks that mimic legitimate ones

### Client Isolation
- **AP Isolation**: Prevents clients from communicating with each other
- **VLAN Segmentation**: Separate networks for different user types

### Monitoring and Logging
- **Security Event Logging**: Tracks authentication failures
- **Intrusion Detection**: Monitors for suspicious activity
- **Regular Security Audits**: Periodic security assessments

### Physical Security
- **Location**: Public vs. private spaces
- **Access Control**: Who can physically access the equipment
- **Surveillance**: Cameras monitoring the area

## Scoring Algorithm

The final security score is calculated as a weighted average:

```
Total Score = (Encryption × 0.40) + (Authentication × 0.15) + 
              (Channel × 0.10) + (Features × 0.20) + 
              (Configuration × 0.10) + (Vendor × 0.05)
```

## Grade Thresholds

- **Excellent (90-100)**: Enterprise-grade security, WPA3, modern features
- **Good (75-89)**: Strong security, WPA2-Enterprise, good features
- **Okay (60-74)**: Adequate security, WPA2-Personal, basic features
- **Bad (40-59)**: Weak security, WPA, limited features
- **Very Bad (0-39)**: Poor security, WEP/Open, minimal features

## Real-World Examples

### Excellent Security (Score: 95)
- **Network**: "CorporateOffice"
- **Encryption**: WPA3-Enterprise
- **Features**: PMF enabled, 6GHz band, 20MHz channels
- **Vendor**: Cisco enterprise equipment
- **Configuration**: Strong signal control, enterprise authentication

### Good Security (Score: 82)
- **Network**: "HomeOffice"
- **Encryption**: WPA2-Enterprise
- **Features**: PMF enabled, 5GHz band, 40MHz channels
- **Vendor**: Netgear business equipment
- **Configuration**: Moderate signal strength, enterprise authentication

### Poor Security (Score: 25)
- **Network**: "GuestWiFi"
- **Encryption**: Open (no encryption)
- **Features**: WPS enabled, 2.4GHz band, congested channels
- **Vendor**: Unknown/cheap equipment
- **Configuration**: Strong signal, guest network patterns

## Recommendations for Network Administrators

1. **Use WPA3 when possible** - Latest security standard
2. **Enable PMF** - Protects against management frame attacks
3. **Disable WPS** - Known security vulnerability
4. **Use 5GHz or 6GHz bands** - Less congestion and interference
5. **Implement enterprise authentication** - Better user management
6. **Control signal strength** - Limit attack surface
7. **Regular firmware updates** - Patch security vulnerabilities
8. **Monitor for rogue APs** - Detect potential attacks
9. **Segment networks** - Separate guest and production traffic
10. **Log security events** - Track authentication and access attempts

This comprehensive approach provides a much more accurate assessment of Wi-Fi network security than encryption type alone.
