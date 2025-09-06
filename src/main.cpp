#include "CommandProcessor.h"
#include <iostream>
#include <stdexcept>

int main() {
    try {
        std::cout << "Wi-Fi Scanner v1.0.0" << std::endl;
        std::cout << "Type 'help' for available commands" << std::endl;
        std::cout << "Type 'exit' to quit" << std::endl;
        std::cout << std::endl;
        
        WifiScanner::CommandProcessor processor;
        processor.run();
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown fatal error occurred" << std::endl;
        return 1;
    }
}
