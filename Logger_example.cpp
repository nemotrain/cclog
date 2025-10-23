#include "src/utils/Logger.hpp"
#include <string>

int main() {
    // Initialize logger
    Logger::getInstance().init();
    
    // Method 1: Using convenience macros (recommended)
    LOG_INFO("Application started");
    LOG_DEBUG("Debug information");
    LOG_WARN("Warning message");
    LOG_ERROR("Error occurred");
    
    // Method 2: Using global logger instance
    g_logger.info("Using global logger instance");
    g_logger.warn("Another warning");
    
    // Method 3: Using getInstance() directly
    Logger::getInstance().trace("Trace message");
    Logger::getInstance().fatal("Fatal error");
    
    // Method 4: Logging variables with automatic string conversion
    int value = 42;
    double pi = 3.14159;
    LOG_INFO_VAR(value);
    LOG_DEBUG_VAR(pi);
    
    // Method 5: Logging with custom messages and variables
    std::string customMsg = "Custom message with value: " + std::to_string(value);
    LOG_INFO(customMsg);
    
    // Shutdown logger
    Logger::getInstance().shutdown();
    
    return 0;
}
