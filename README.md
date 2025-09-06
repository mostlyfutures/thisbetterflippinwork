<<<<<<< HEAD
# vrw243f24f23
=======
# Wi-Fi Scanner

A cross-platform command-line Wi-Fi network scanner written in C++ that provides security grading for detected networks.

## Features

- **Cross-platform support**: Windows, macOS, and Linux
- **Command-line interface**: Custom commands with a `wifi-cli>` prompt
- **Wi-Fi scanning**: Detects nearby networks and their properties
- **Security grading**: Rates networks from "Very Bad" to "Excellent"
- **Network information**: SSID, BSSID, security type, signal strength, channel, frequency

## Commands

- `scan` or `s` - Scan for nearby Wi-Fi networks
- `help` or `h` or `?` - Show help information
- `version` or `v` - Show version information
- `exit` or `quit` or `q` - Exit the application

## Building

### Prerequisites

- CMake 3.16 or higher
- C++17 compatible compiler
- Platform-specific dependencies (see below)

### Build Instructions

```bash
mkdir build
cd build
cmake ..
make
```

### Platform-Specific Dependencies

#### macOS
- CoreWLAN framework (built-in)
- Xcode Command Line Tools

#### Windows
- Visual Studio with C++ support
- Windows SDK

#### Linux
- NetworkManager development libraries
- `libnm-dev` package (Ubuntu/Debian)
- `networkmanager-devel` package (Fedora/RHEL)

## Project Structure

```
├── CMakeLists.txt          # Build configuration
├── include/                # Header files
│   ├── NetworkInfo.h       # Network data structures
│   ├── WifiScanner.h       # Abstract scanner interface
│   ├── SecurityGrader.h    # Security rating logic
│   ├── CommandProcessor.h  # Command-line interface
│   └── platforms/          # Platform-specific headers
│       ├── MacWifiScanner.h
│       ├── WindowsWifiScanner.h
│       └── LinuxWifiScanner.h
├── src/                    # Source files
│   ├── main.cpp            # Application entry point
│   ├── WifiScanner.cpp     # Factory implementation
│   ├── SecurityGrader.cpp  # Security grading logic
│   ├── CommandProcessor.cpp # CLI implementation
│   └── platforms/          # Platform-specific implementations
│       ├── MacWifiScanner.cpp
│       ├── WindowsWifiScanner.cpp
│       └── LinuxWifiScanner.cpp
└── README.md               # This file
```

## Security Grading

Networks are graded based on:

- **Encryption type**: WPA3 > WPA2-Enterprise > WPA2-Personal > WPA > WEP > Open
- **Enterprise vs Personal**: Enterprise networks get bonus points
- **Hidden networks**: Slight penalty for security through obscurity

### Grade Scale

- **Excellent (90-100)**: WPA3 networks
- **Good (75-89)**: WPA2-Enterprise networks
- **Okay (60-74)**: WPA2-Personal networks
- **Bad (40-59)**: WPA networks
- **Very Bad (0-39)**: WEP or open networks

## Usage Example

```bash
$ ./wifi-scanner
Wi-Fi Scanner v1.0.0
Type 'help' for available commands
Type 'exit' to quit

wifi-cli> scan
Scanning for Wi-Fi networks...
Found 8 network(s):

SSID                 BSSID              Security        Grade     Signal   Channel
--------------------------------------------------------------------------------
MyNetwork            AA:BB:CC:DD:EE:FF  WPA2-Personal   Okay      -45      6
GuestWiFi           11:22:33:44:55:66  Open            Very Bad  -52      1
OfficeNetwork       99:88:77:66:55:44  WPA2-Enterprise Good      -38      11

wifi-cli> exit
Goodbye!
```

## Development Status

- ✅ Project structure and build system
- ✅ Command-line interface
- ✅ Security grading system
- ✅ macOS implementation (CoreWLAN)
- 🔄 Windows implementation (WlanAPI) - TODO
- 🔄 Linux implementation (NetworkManager/iw) - TODO

## Contributing

This project is designed to be easily extensible. To add support for a new platform:

1. Create a new class that inherits from `WifiScanner`
2. Implement the required virtual methods
3. Add the platform detection logic in `WifiScanner.cpp`
4. Update `CMakeLists.txt` with platform-specific dependencies

## License

This project is open source. Feel free to use and modify as needed.

## Troubleshooting

### Common Issues

**"Wi-Fi scanning is not supported on this platform"**
- Ensure you have the required platform-specific dependencies installed
- Check that your Wi-Fi adapter is working and enabled

**Build errors on macOS**
- Install Xcode Command Line Tools: `xcode-select --install`
- Ensure you're using a compatible C++ compiler

**Permission denied errors**
- Some platforms require elevated privileges for Wi-Fi scanning
- Try running with appropriate permissions or as administrator/root
>>>>>>> ec05a5e (first commit)
