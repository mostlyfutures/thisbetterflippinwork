cmake_minimum_required(VERSION 3.16)
project(WifiScanner VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable testing
enable_testing()

# Platform detection
if(WIN32)
    set(PLATFORM_WINDOWS TRUE)
elseif(APPLE)
    set(PLATFORM_MACOS TRUE)
elseif(UNIX)
    set(PLATFORM_LINUX TRUE)
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/CommandProcessor.cpp
    src/WifiScanner.cpp
    src/SecurityGrader.cpp
)

# Platform-specific source files
if(PLATFORM_WINDOWS)
    list(APPEND SOURCES src/platforms/WindowsWifiScanner.cpp)
elseif(PLATFORM_MACOS)
    list(APPEND SOURCES src/platforms/MacWifiScanner.cpp)
elseif(PLATFORM_LINUX)
    list(APPEND SOURCES src/platforms/LinuxWifiScanner.cpp)
endif()

# Headers
set(HEADERS
    include/CommandProcessor.h
    include/WifiScanner.h
    include/SecurityGrader.h
    include/NetworkInfo.h
    include/platforms/WindowsWifiScanner.h
    include/platforms/MacWifiScanner.h
    include/platforms/LinuxWifiScanner.h
)

# Test files
set(TEST_SOURCES
    tests/test_security_grader.cpp
)

# Benchmark tools
set(BENCHMARK_SOURCES
    tools/benchmark.cpp
)

# Create main executable
add_executable(wifi-scanner ${SOURCES} ${HEADERS})

# Create test executable
add_executable(test_security_grader ${TEST_SOURCES} src/CommandProcessor.cpp src/WifiScanner.cpp src/SecurityGrader.cpp src/platforms/MacWifiScanner.cpp ${HEADERS})

# Create benchmark executable
add_executable(benchmark ${BENCHMARK_SOURCES} src/CommandProcessor.cpp src/WifiScanner.cpp src/SecurityGrader.cpp src/platforms/MacWifiScanner.cpp ${HEADERS})

# Include directories
target_include_directories(wifi-scanner PRIVATE include)
target_include_directories(test_security_grader PRIVATE include)
target_include_directories(benchmark PRIVATE include)

# Platform-specific libraries and flags
if(PLATFORM_WINDOWS)
    target_link_libraries(wifi-scanner wlanapi ole32 oleaut32 iphlpapi)
    target_link_libraries(test_security_grader wlanapi ole32 oleaut32 iphlpapi)
    target_link_libraries(benchmark wlanapi ole32 oleaut32 iphlpapi)
elseif(PLATFORM_MACOS)
    find_library(COREWLAN_FRAMEWORK CoreWLAN)
    find_library(FOUNDATION_FRAMEWORK Foundation)
    target_link_libraries(wifi-scanner ${COREWLAN_FRAMEWORK} ${FOUNDATION_FRAMEWORK})
    target_link_libraries(test_security_grader ${COREWLAN_FRAMEWORK} ${FOUNDATION_FRAMEWORK})
    target_link_libraries(benchmark ${COREWLAN_FRAMEWORK} ${FOUNDATION_FRAMEWORK})
    set_source_files_properties(src/platforms/MacWifiScanner.cpp PROPERTIES COMPILE_FLAGS "-x objective-c++")
elseif(PLATFORM_LINUX)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(NM libnm)
    target_include_directories(wifi-scanner PRIVATE ${NM_INCLUDE_DIRS})
    target_include_directories(test_security_grader PRIVATE ${NM_INCLUDE_DIRS})
    target_include_directories(benchmark PRIVATE ${NM_INCLUDE_DIRS})
    target_link_libraries(wifi-scanner ${NM_LIBRARIES})
    target_link_libraries(test_security_grader ${NM_LIBRARIES})
    target_link_libraries(benchmark ${NM_LIBRARIES})
endif()

# Compiler-specific optimizations
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(wifi-scanner PRIVATE -O3 -march=native)
    target_compile_options(test_security_grader PRIVATE -O3 -march=native)
    target_compile_options(benchmark PRIVATE -O3 -march=native)
elseif(MSVC)
    target_compile_options(wifi-scanner PRIVATE /O2)
    target_compile_options(test_security_grader PRIVATE /O2)
    target_compile_options(benchmark PRIVATE /O2)
endif()

# Add tests
add_test(NAME SecurityGraderTests COMMAND test_security_grader)

# Installation
install(TARGETS wifi-scanner test_security_grader benchmark DESTINATION bin)

# Create package
set(CPACK_PACKAGE_NAME "WiFiScanner")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Advanced Cross-Platform Wi-Fi Security Scanner")
set(CPACK_PACKAGE_VENDOR "WiFiScanner Team")
set(CPACK_PACKAGE_CONTACT "support@wifiscanner.com")

if(PLATFORM_WINDOWS)
    set(CPACK_GENERATOR "NSIS")
elseif(PLATFORM_MACOS)
    set(CPACK_GENERATOR "DragNDrop")
elseif(PLATFORM_LINUX)
    set(CPACK_GENERATOR "DEB")
endif()

include(CPack)
