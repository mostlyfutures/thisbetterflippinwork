#!/bin/bash

# Wi-Fi Scanner Build Script
# This script automates the build process for the Wi-Fi Scanner project

set -e  # Exit on any error

echo "Building Wi-Fi Scanner..."

# Check if CMake is installed
if ! command -v cmake &> /dev/null; then
    echo "Error: CMake is not installed. Please install CMake 3.16 or higher."
    exit 1
fi

# Check CMake version
CMAKE_VERSION=$(cmake --version | head -n1 | cut -d' ' -f3)
CMAKE_MAJOR=$(echo $CMAKE_VERSION | cut -d'.' -f1)
CMAKE_MINOR=$(echo $CMAKE_VERSION | cut -d'.' -f2)

if [ "$CMAKE_MAJOR" -lt 3 ] || ([ "$CMAKE_MAJOR" -eq 3 ] && [ "$CMAKE_MINOR" -lt 16 ]); then
    echo "Error: CMake version $CMAKE_VERSION is too old. Please install CMake 3.16 or higher."
    exit 1
fi

echo "CMake version: $CMAKE_VERSION"

# Create build directory
if [ -d "build" ]; then
    echo "Removing existing build directory..."
    rm -rf build
fi

echo "Creating build directory..."
mkdir build
cd build

# Configure with CMake
echo "Configuring project with CMake..."
cmake ..

# Build the project
echo "Building project..."
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo ""
echo "Build completed successfully!"
echo "Executable: build/wifi-scanner"
echo ""
echo "To run the application:"
echo "  cd build"
echo "  ./wifi-scanner"
echo ""
echo "Or run directly:"
echo "  ./build/wifi-scanner"
