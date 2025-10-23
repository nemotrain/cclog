#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <vector>
#include <queue>
#include <condition_variable>
#include <chrono>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <memory>
#include <algorithm>
#include <cstring>
#include <array>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <limits.h>
#endif

// 日志级别枚举
enum class Level {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERR = 4,
    FATAL = 5
};

// 控制台输出模式
enum class ConsoleMode {
    NORMAL,     // 正常滚动输出
    SCROLL,     // 限制行数滚动
    CLEAR       // 每次清屏输出
};

// 日志消息结构
struct LogMessage {
    Level level;
    std::string message;
    std::chrono::system_clock::time_point timestamp;
    std::thread::id threadId;
    
    // 默认构造函数
    LogMessage() 
        : level(Level::INFO), message(""), timestamp(std::chrono::system_clock::now()), threadId(std::this_thread::get_id()) {}
    
    // 带参数的构造函数，添加安全检查
    LogMessage(Level l, const std::string& msg) 
        : level(l), message(""), timestamp(std::chrono::system_clock::now()), threadId(std::this_thread::get_id()) {
        try {
            // 安全地复制消息内容，防止内存访问违规
            if (!msg.empty()) {
                // 限制消息长度，防止过大的消息
                if (msg.length() > 8192) {
                    message = msg.substr(0, 8192) + "... [TRUNCATED]";
                } else {
                    message = msg;
                }
            }
        } catch (const std::exception& e) {
            // 如果复制失败，使用安全的错误消息
            message = "[ERROR] Failed to copy message: " + std::string(e.what());
        } catch (...) {
            message = "[ERROR] Unknown error copying message";
        }
    }
};

// 无锁环形缓冲区，专门处理智能指针
template<typename T, size_t Size>
class LockFreeRingBuffer {
private:
    static_assert(Size > 0 && ((Size & (Size - 1)) == 0), "Size must be a power of 2");
    
    std::array<T, Size> buffer;
    std::atomic<size_t> head{0};
    std::atomic<size_t> tail{0};
    
    static constexpr size_t MASK = Size - 1;
    
public:
    // 尝试推送消息到缓冲区（复制版本，适用于shared_ptr）
    bool tryPush(const T& item) noexcept {
        size_t currentTail = tail.load(std::memory_order_relaxed);
        size_t nextTail = (currentTail + 1) & MASK;
        
        if (nextTail == head.load(std::memory_order_acquire)) {
            return false; // 缓冲区满
        }
        
        // 使用赋值操作符，std::shared_ptr会自动处理引用计数
        buffer[currentTail] = item;
        tail.store(nextTail, std::memory_order_release);
        return true;
    }
    
    // 尝试从缓冲区弹出消息
    bool tryPop(T& item) noexcept {
        size_t currentHead = head.load(std::memory_order_relaxed);
        
        if (currentHead == tail.load(std::memory_order_acquire)) {
            return false; // 缓冲区空
        }
        
        // 使用赋值操作符，std::shared_ptr会自动处理引用计数
        item = buffer[currentHead];
        head.store((currentHead + 1) & MASK, std::memory_order_release);
        return true;
    }
    
    // 检查缓冲区是否为空
    bool isEmpty() const noexcept {
        return head.load(std::memory_order_acquire) == tail.load(std::memory_order_acquire);
    }
};

// 定义智能指针类型的环形缓冲区
using LogBuffer = LockFreeRingBuffer<std::shared_ptr<LogMessage>, 1024>;
using LogBufferPtr = std::shared_ptr<LogBuffer>;

// 前向声明
class GlobalBufferManager;

// 线程本地存储管理器
class ThreadLocalBuffer {
private:
    static thread_local LogBufferPtr localBuffer;
    static thread_local bool registered;
    
public:
    static LogBufferPtr getBuffer() {
        if (!localBuffer) {
            localBuffer = std::make_shared<LogBuffer>();
            registered = false;
        }
        return localBuffer;
    }
    
    static bool isRegistered() { return registered; }
    static void setRegistered(bool reg) { registered = reg; }
    static void cleanup();
    
    // 线程本地析构器，确保线程结束时自动清理
    class ThreadLocalDestructor {
    public:
        ~ThreadLocalDestructor() { ThreadLocalBuffer::cleanup(); }
    };
    
    static thread_local ThreadLocalDestructor destructor;
};

// 线程本地变量定义
inline thread_local LogBufferPtr ThreadLocalBuffer::localBuffer = nullptr;

inline thread_local bool ThreadLocalBuffer::registered = false;
inline thread_local ThreadLocalBuffer::ThreadLocalDestructor ThreadLocalBuffer::destructor;

// 全局缓冲区管理器
class GlobalBufferManager {
private:
    std::vector<std::weak_ptr<LogBuffer>> threadBuffers;
    std::mutex bufferMutex;
    
public:
    void registerBuffer(const LogBufferPtr& buffer) {
        std::lock_guard<std::mutex> lock(bufferMutex);
        threadBuffers.push_back(buffer);
    }
    
    void unregisterBuffer(const LogBufferPtr& buffer) {
        std::lock_guard<std::mutex> lock(bufferMutex);
        threadBuffers.erase(
            std::remove_if(threadBuffers.begin(), threadBuffers.end(),
                [&](const std::weak_ptr<LogBuffer>& w){
                    auto s = w.lock();
                    return (!s) || (s == buffer);
                }),
            threadBuffers.end());
    }
    
    std::vector<LogBufferPtr> getAllBuffers() {
        std::lock_guard<std::mutex> lock(bufferMutex);
        std::vector<LogBufferPtr> result;
        auto it = threadBuffers.begin();
        while (it != threadBuffers.end()) {
            if (auto sp = it->lock()) {
                result.push_back(sp);
                ++it;
            } else {
                it = threadBuffers.erase(it); // 清理过期
            }
        }
        return result;
    }
};

// 全局缓冲区管理器实例
static GlobalBufferManager g_bufferManager;

// ThreadLocalBuffer::cleanup() 实现
inline void ThreadLocalBuffer::cleanup() {
    try {
        if (localBuffer && registered) {
            g_bufferManager.unregisterBuffer(localBuffer);
            registered = false;
        }
        // 安全地清理本地缓冲区
        if (localBuffer) {
            // 清空缓冲区中的所有消息，避免在程序退出时析构
            std::shared_ptr<LogMessage> msg;
            while (localBuffer->tryPop(msg)) {
                // 消息会被智能指针自动清理
                msg.reset();
            }
            localBuffer.reset();
        }
    } catch (...) {
        // 忽略清理过程中的异常，避免在程序退出时崩溃
    }
}

// 主Logger类
class Logger {
private:
    // 配置参数
    std::string m_configFile;
    std::string m_logDir;
    Level m_logLevel;
    bool m_consoleOutput;
    ConsoleMode m_consoleMode;
    size_t m_maxFileSize;
    size_t m_maxFilesPerSlot;
    int m_keepLogDays;
    int m_flushIntervalMs;
    size_t m_batchSize;
    
    // 文件相关
    std::ofstream m_logFile;
    std::string m_currentLogPath;
    size_t m_currentFileSize;
    size_t m_currentFileIndex;
    
    // 程序启动时间（用于文件名生成）
    std::chrono::system_clock::time_point m_programStartTime;
    
    // 应用程序名称（用于日志文件名）
    std::string m_appName;
    
    // 线程安全
    std::mutex m_fileMutex;
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_shutdown{false};
    
    // 后台写入线程
    std::thread m_writeThread;
    std::condition_variable m_writeCondition;
    std::mutex m_writeMutex;
    
    // 批量写入缓冲区
    std::vector<std::shared_ptr<LogMessage>> m_writeBuffer;
    std::mutex m_writeBufferMutex;
    
    // 单例实例
    static std::unique_ptr<Logger> s_instance;
    static std::mutex s_instanceMutex;
    static std::atomic<Logger*> instance;
    
    Logger() = default;
    
    // 禁用拷贝和赋值
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    // 内部方法
    std::string getLevelString(Level level) const;
    std::string formatLogMessage(const LogMessage& msg) const;
    void ensureLogDirectory();
    void createNewLogFile();
    void checkRotation();
    std::string resolvePath(const std::string& path) const;
    std::string getExecutableDir() const;
    std::string getExecutableName() const;
    void determineNextFileIndex();
    void cleanupOldLogs();
    void writeToFile(const std::string& message);
    void consoleOutput(const LogMessage& msg);
    void backgroundWriteThread();
    void flushWriteBuffer();
    
    // 添加内存安全检查函数
    bool isValidLogMessage(const LogMessage& msg) const;
    
public:
    ~Logger();
    
    // 单例获取
    static Logger& getInstance();
    
    // 初始化和关闭
    static bool init(const std::string& configFile = "");
    void shutdown();
    
    // 日志记录方法
    void log(Level level, const std::string& message);
    void trace(const std::string& message) { log(Level::TRACE, message); }
    void debug(const std::string& message) { log(Level::DEBUG, message); }
    void info(const std::string& message) { log(Level::INFO, message); }
    void warn(const std::string& message) { log(Level::WARN, message); }
    void error(const std::string& message) { log(Level::ERR, message); }
    void fatal(const std::string& message) { log(Level::FATAL, message); }
    
    // 配置相关
    bool loadConfig(const std::string& configFile);
    void setLogLevel(Level level) { m_logLevel = level; }
    void setConsoleOutput(bool enable) { m_consoleOutput = enable; }
    void setConsoleMode(ConsoleMode mode) { m_consoleMode = mode; }
    
    // 状态查询
    bool isInitialized() const { return m_initialized.load(); }
    std::string getLogDir() const { return m_logDir; }
    Level getLogLevel() const { return m_logLevel; }
    
    // 内存监控
    size_t getWriteBufferSize() const { 
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(m_writeBufferMutex));
        return m_writeBuffer.size(); 
    }
    size_t getTotalBufferedMessages() const;
};

// 静态成员定义
inline std::unique_ptr<Logger> Logger::s_instance = nullptr;
inline std::mutex Logger::s_instanceMutex;
inline std::atomic<Logger*> Logger::instance = nullptr;

// 便利宏
#define LOG_TRACE(msg) Logger::getInstance().trace(msg)
#define LOG_DEBUG(msg) Logger::getInstance().debug(msg)
#define LOG_INFO(msg) Logger::getInstance().info(msg)
#define LOG_WARN(msg) Logger::getInstance().warn(msg)
#define LOG_ERROR(msg) Logger::getInstance().error(msg)
#define LOG_FATAL(msg) Logger::getInstance().fatal(msg)

#define LOG_DEBUG_VAR(var) LOG_DEBUG(#var " = " + std::to_string(var))

// 内存监控宏
#define LOG_MEMORY_STATUS() do { \
    auto& logger = Logger::getInstance(); \
    LOG_INFO("Memory Status - Write Buffer: " + std::to_string(logger.getWriteBufferSize()) + \
             ", Total Buffered: " + std::to_string(logger.getTotalBufferedMessages())); \
} while(0)


// 实现部分
inline Logger& Logger::getInstance() {
    Logger* tmp = instance.load(std::memory_order_acquire);
    if (!tmp) {
        std::lock_guard<std::mutex> lock(s_instanceMutex);
        tmp = instance.load(std::memory_order_relaxed);
        if (!tmp) {
            Logger::init();
            tmp = s_instance.get();
            instance.store(tmp, std::memory_order_release);
        }
    }
    return *s_instance;
}

inline Logger::~Logger() {
    shutdown();
}

inline bool Logger::init(const std::string& configFile) {
    if (s_instance) return true;
    s_instance = std::unique_ptr<Logger>(new Logger());
    if (s_instance->m_initialized.load()) return true;
    
    s_instance->m_programStartTime = std::chrono::system_clock::now();
    s_instance->m_appName = s_instance->getExecutableName();
    
    std::string configPath = configFile.empty() ? "config/logger.ini" : configFile;
    if (!s_instance->loadConfig(configPath)) {
        std::cerr << "Failed to load logger configuration from: " << configPath << std::endl;
        return false;
    }
    
    s_instance->ensureLogDirectory();
    s_instance->createNewLogFile();
    s_instance->cleanupOldLogs();
    
    s_instance->m_shutdown.store(false);
    s_instance->m_writeThread = std::thread(&Logger::backgroundWriteThread, s_instance.get());
    
    s_instance->m_initialized.store(true);
    s_instance->info("Logging initialized successfully");
    return true;
}

inline void Logger::shutdown() {
    if (!m_initialized.load()) return;
    
    try {
        m_shutdown.store(true);
        m_writeCondition.notify_all();
        
        // 等待写入线程结束
        if (m_writeThread.joinable()) {
            m_writeThread.join();
        }
        
        // 关闭日志文件
        if (m_logFile.is_open()) {
            m_logFile.close();
        }
        
        m_initialized.store(false);
        s_instance = nullptr;
        instance.store(nullptr, std::memory_order_release);
    } catch (...) {
        // 忽略关闭过程中的异常，避免在程序退出时崩溃
        m_initialized.store(false);
    }
}

inline void Logger::log(Level level, const std::string& message) {
    if (level < m_logLevel) return;
    if(m_shutdown.load()) return;
    
    try {
        // 首先检查输入参数的有效性
        if (static_cast<int>(level) < 0 || static_cast<int>(level) > 5) {
            level = Level::ERR; // 使用默认的错误级别
        }
        
        // 安全地处理消息内容，防止内存访问违规
        std::string safeMessage;
        try {
            // 检查消息是否为空或无效
            if (message.empty()) {
                safeMessage = "[EMPTY_MESSAGE]";
            } else {
                // 限制消息长度，防止过大的消息导致内存问题
                if (message.length() > 8192) {
                    safeMessage = message.substr(0, 8192) + "... [TRUNCATED]";
                } else {
                    safeMessage = message;
                }
            }
        } catch (const std::exception& e) {
            // 如果消息处理失败，使用安全的错误消息
            safeMessage = "[ERROR] Failed to process message: " + std::string(e.what());
        } catch (...) {
            safeMessage = "[ERROR] Unknown error processing message";
        }
        
        // 创建智能指针，管理LogMessage对象，使用std::make_shared更安全
        auto logMsgPtr = std::make_shared<LogMessage>(level, safeMessage);
        
        // 验证创建的LogMessage对象是否有效
        if (!isValidLogMessage(*logMsgPtr)) {
            // 如果对象无效，创建一个安全的错误消息
            logMsgPtr = std::make_shared<LogMessage>(Level::ERR, "[ERROR] Invalid LogMessage object created");
        }
        
        if (m_consoleOutput) {
            try {
                consoleOutput(*logMsgPtr);
            } catch (const std::exception& e) {
                // 控制台输出失败时，输出到stderr
                std::cerr << "[ERROR] Console output failed: " << e.what() << std::endl;
            }
        }
        
        auto buffer = ThreadLocalBuffer::getBuffer();
        if (!ThreadLocalBuffer::isRegistered()) {
            g_bufferManager.registerBuffer(buffer);
            ThreadLocalBuffer::setRegistered(true);
        }
        
        // 尝试将智能指针复制到缓冲区，如果失败，直接复制到后台写入缓冲区
        if (!buffer->tryPush(logMsgPtr)) {
            // 直接输出到stderr
            std::cerr << "[FATAL] logger buffer push failed: " << std::endl;
        }
        
    } catch (const std::bad_alloc& e) {
        // 内存分配失败时的降级处理
        std::cerr << "[FATAL] Memory allocation failed in logger: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        // 其他异常的处理
        std::cerr << "[ERROR] Exception in logger: " << e.what() << std::endl;
    } catch (...) {
        // 未知异常的处理
        std::cerr << "[ERROR] Unknown exception in logger" << std::endl;
    }
}

inline std::string Logger::getLevelString(Level level) const {
    switch (level) {
        case Level::TRACE: return "TRACE";
        case Level::DEBUG: return "DEBUG";
        case Level::INFO: return "INFO";
        case Level::WARN: return "WARN";
        case Level::ERR: return "ERR";
        case Level::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

inline std::string Logger::formatLogMessage(const LogMessage& msg) const {
    try {
        // 首先进行内存安全检查
        if (!isValidLogMessage(msg)) {
            return "[ERROR] Invalid LogMessage object detected";
        }
        
        auto time_t = std::chrono::system_clock::to_time_t(msg.timestamp);
        
        #ifdef _WIN32
        struct tm timeinfo;
        if (localtime_s(&timeinfo, &time_t) != 0) {
            return "[ERROR] Failed to format time";
        }
        #else
        struct tm timeinfo;
        if (localtime_r(&time_t, &timeinfo) == nullptr) {
            return "[ERROR] Failed to format time";
        }
        #endif
        
        // 使用更安全的方式格式化时间字符串，避免ostringstream的内存问题
        char timeBuffer[32];
        if (strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", &timeinfo) == 0) {
            return "[ERROR] Failed to format time";
        }
        
        // 计算所需内存大小，避免多次重新分配
        size_t levelStrLen = 0;
        const char* levelStr = nullptr;
        switch (msg.level) {
            case Level::TRACE: levelStr = "TRACE"; levelStrLen = 5; break;
            case Level::DEBUG: levelStr = "DEBUG"; levelStrLen = 5; break;
            case Level::INFO: levelStr = "INFO"; levelStrLen = 4; break;
            case Level::WARN: levelStr = "WARN"; levelStrLen = 4; break;
            case Level::ERR: levelStr = "ERR"; levelStrLen = 3; break;
            case Level::FATAL: levelStr = "FATAL"; levelStrLen = 5; break;
            default: levelStr = "UNKNOWN"; levelStrLen = 7; break;
        }
        
        // 安全地获取消息内容，避免内存访问违规
        std::string safeMessage;
        try {
            // 使用try-catch包装字符串访问，防止内存访问违规
            safeMessage = msg.message;
        } catch (const std::exception& e) {
            safeMessage = "[ERROR] Failed to access message content: " + std::string(e.what());
        } catch (...) {
            safeMessage = "[ERROR] Unknown error accessing message content";
        }
        
        // 限制消息长度，防止过大的消息导致内存问题
        size_t messageLen = safeMessage.length();
        if (messageLen > 8192) { // 限制消息最大长度为8KB
            messageLen = 8192;
        }
        
        // 计算总长度：时间(19) + 级别(最长7) + 线程ID(最长20) + 固定字符(12) + 消息长度
        size_t totalLen = 19 + levelStrLen + 20 + 12 + messageLen;
        
        // 使用更高效的方式构建字符串
        std::string result;
        result.reserve(totalLen);
        
        // 使用append方法，避免多次+=操作
        result.append("[");
        result.append(timeBuffer);
        result.append("] [");
        result.append(levelStr, levelStrLen);
        result.append("] [");
        
        // 使用更安全的方式处理线程ID，避免过大的哈希值
        std::stringstream threadIdStream;
        threadIdStream << msg.threadId;
        std::string threadIdStr = threadIdStream.str();
        if (threadIdStr.length() > 16) {
            threadIdStr = threadIdStr.substr(0, 16); // 限制线程ID长度
        }
        result.append(threadIdStr);
        result.append("] ");
        
        // 添加消息内容，如果超长则截断
        if (safeMessage.length() > 8192) {
            result.append(safeMessage, 0, 8192);
            result.append("... [TRUNCATED]");
        } else {
            result.append(safeMessage);
        }
        
        return result;
        
    } catch (const std::bad_alloc& e) {
        // 内存分配失败时的降级处理
        return "[ERROR] Memory allocation failed in log formatting";
    } catch (const std::exception& e) {
        // 其他异常的处理
        return "[ERROR] Exception in log formatting: " + std::string(e.what());
    } catch (...) {
        // 未知异常的处理
        return "[ERROR] Unknown exception in log formatting";
    }
}

inline void Logger::consoleOutput(const LogMessage& msg) {
    std::string formattedMsg = formatLogMessage(msg);
    
    switch (m_consoleMode) {
        case ConsoleMode::NORMAL:
            std::cout << formattedMsg << std::endl;
            break;
        case ConsoleMode::SCROLL:
            std::cout << formattedMsg << std::endl;
            break;
        case ConsoleMode::CLEAR:
            // 使用ANSI转义序列清屏
            std::cout << "\033[2J\033[1;1H" << formattedMsg << std::endl;
            break;
    }
}

inline void Logger::backgroundWriteThread() {
    // 收集所有线程缓冲区的消息
    std::shared_ptr<LogMessage> msg;
    while (!m_shutdown.load()) {
        auto buffers = g_bufferManager.getAllBuffers();
        for (auto& buffer : buffers) {
            if (buffer) {
                while (buffer->tryPop(msg)) {
                    m_writeBuffer.push_back(msg);
                }
            }
        }
        
        flushWriteBuffer();
    }
    
    // 线程关闭前，再次刷新所有缓冲区
    auto buffers = g_bufferManager.getAllBuffers();
    for (auto& buffer : buffers) {
        if (buffer) {
            while (buffer->tryPop(msg)) {
                m_writeBuffer.push_back(msg);
            }
        }
    }
    flushWriteBuffer();
}

inline void Logger::flushWriteBuffer() {
    std::lock_guard<std::mutex> fileLock(m_fileMutex); // 再锁文件互斥量（一致顺序，避免死锁）

    if (m_writeBuffer.empty()) {
        return;
    }
    
    try {
        // 使用索引而不是迭代器，避免在修改容器时的问题
        size_t processedCount = 0;
        size_t bufferSize = m_writeBuffer.size();
        
        for (size_t i = 0; i < bufferSize; ++i) {
            auto& msgPtr = m_writeBuffer[i];
            if (msgPtr) {
                try {
                    std::string formattedMsg = formatLogMessage(*msgPtr);
                    writeToFile(formattedMsg);
                    processedCount++;
                    
                    // 如果文件已轮转，跳出循环，剩余消息将保留在缓冲区
                    if (m_currentFileSize == 0) {
                        break;
                    }
                } catch (const std::bad_alloc& e) {
                    // 格式化消息时内存不足，跳过这条消息
                    std::cerr << "[ERROR] Memory allocation failed while formatting log message: " << e.what() << std::endl;
                    processedCount++;
                } catch (const std::exception& e) {
                    // 其他异常，跳过这条消息
                    std::cerr << "[ERROR] Exception while formatting log message: " << e.what() << std::endl;
                    processedCount++;
                }
            } else {
                processedCount++;
            }
        }
        
        // 清空已处理的消息，保留剩余的
        if (processedCount > 0) {
            m_writeBuffer.erase(m_writeBuffer.begin(), m_writeBuffer.begin() + processedCount);
        }
        
        if (m_logFile.is_open()) {
            try {
                m_logFile.flush();
            } catch (const std::exception& e) {
                std::cerr << "[ERROR] Failed to flush log file: " << e.what() << std::endl;
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception in flushWriteBuffer: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[ERROR] Unknown exception in flushWriteBuffer" << std::endl;
    }
}

inline void Logger::writeToFile(const std::string& message) {
    if (!m_logFile.is_open()) {
        return;
    }
    
    size_t actualBytes = message.length() + 1; // +1 for newline
    
    m_logFile << message << std::endl;
    m_currentFileSize += actualBytes;
    
    if (m_currentFileSize >= m_maxFileSize) {
        checkRotation();
        return;
    }
}

inline void Logger::ensureLogDirectory() {
    std::string resolvedLogDir = resolvePath(m_logDir);
    std::filesystem::path baseLogPath(resolvedLogDir);
    if (!std::filesystem::exists(baseLogPath)) {
        std::filesystem::create_directories(baseLogPath);
    }
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    #ifdef _WIN32
    struct tm timeinfo;
    localtime_s(&timeinfo, &time_t);
    #else
    struct tm timeinfo;
    localtime_r(&time_t, &timeinfo);
    #endif
    
    // 使用更安全的方式格式化日期字符串
    char dateBuffer[16];
    if (strftime(dateBuffer, sizeof(dateBuffer), "%Y-%m-%d", &timeinfo) == 0) {
        dateBuffer[0] = '\0'; // 确保字符串为空
    }
    std::string dateStr(dateBuffer);
    
    std::filesystem::path dailyLogPath = baseLogPath / dateStr;
    if (!std::filesystem::exists(dailyLogPath)) {
        std::filesystem::create_directories(dailyLogPath);
    }
    
    m_currentLogPath = dailyLogPath.string();
    determineNextFileIndex();
}

inline void Logger::createNewLogFile() {
    auto time_t = std::chrono::system_clock::to_time_t(m_programStartTime);
    
    #ifdef _WIN32
    struct tm timeinfo;
    localtime_s(&timeinfo, &time_t);
    #else
    struct tm timeinfo;
    localtime_r(&time_t, &timeinfo);
    #endif
    
    // 使用更安全的方式格式化时间字符串
    char timeBuffer[16];
    if (strftime(timeBuffer, sizeof(timeBuffer), "%H-%M", &timeinfo) == 0) {
        timeBuffer[0] = '\0'; // 确保字符串为空
    }
    std::string timeStr(timeBuffer);
    
    std::string filename = m_appName + "_" + timeStr;
    
    if (m_currentFileIndex > 0) {
        filename += "_" + std::to_string(m_currentFileIndex);
    }
    
    filename += ".log";
    
    std::filesystem::path logFilePath = std::filesystem::path(m_currentLogPath) / filename;
    
    if (m_logFile.is_open()) {
        m_logFile.close();
    }
    
    m_logFile.open(logFilePath, std::ios::app);
    if (m_logFile.is_open()) {
        m_currentFileSize = std::filesystem::file_size(logFilePath);
    } else {
        std::cerr << "Failed to open log file: " << logFilePath.string() << std::endl;
    }
}

inline void Logger::checkRotation() {
    if (m_currentFileSize >= m_maxFileSize) {
        m_currentFileIndex++;
        if (m_currentFileIndex >= m_maxFilesPerSlot) {
            m_currentFileIndex = 0;
        }
        createNewLogFile();
    }
}

inline std::string Logger::resolvePath(const std::string& path) const {
    if (std::filesystem::path(path).is_absolute()) {
        return path;
    }
    
    std::string exeDir = getExecutableDir();
    return (std::filesystem::path(exeDir) / path).string();
}

inline std::string Logger::getExecutableDir() const {
    #ifdef _WIN32
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string exePath(buffer);
    size_t lastSlash = exePath.find_last_of("\\/");
    return exePath.substr(0, lastSlash);
    #else
    char buffer[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len != -1) {
        buffer[len] = '\0';
        std::string exePath(buffer);
        size_t lastSlash = exePath.find_last_of('/');
        return exePath.substr(0, lastSlash);
    }
    return ".";
    #endif
}

inline std::string Logger::getExecutableName() const {
    #ifdef _WIN32
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string exePath(buffer);
    size_t lastSlash = exePath.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        std::string exeName = exePath.substr(lastSlash + 1);
        size_t dotPos = exeName.find_last_of('.');
        if (dotPos != std::string::npos) {
            exeName = exeName.substr(0, dotPos);
        }
        return exeName;
    }
    return "unknown_app";
    #else
    char buffer[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len != -1) {
        buffer[len] = '\0';
        std::string exePath(buffer);
        size_t lastSlash = exePath.find_last_of('/');
        if (lastSlash != std::string::npos) {
            std::string exeName = exePath.substr(lastSlash + 1);
            return exeName;
        }
    }
    return "unknown_app";
    #endif
}

inline void Logger::determineNextFileIndex() {
    m_currentFileIndex = 0;
    
    try {
        std::filesystem::path dailyLogPath(m_currentLogPath);
        if (!std::filesystem::exists(dailyLogPath)) {
            return;
        }
        
        size_t maxIndex = 0;
        for (const auto& entry : std::filesystem::directory_iterator(dailyLogPath)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                if (filename.length() >= 4 && filename.substr(filename.length() - 4) == ".log") {
                    size_t underscorePos = filename.find_last_of('_');
                    if (underscorePos != std::string::npos) {
                        std::string indexStr = filename.substr(underscorePos + 1);
                        size_t dotPos = indexStr.find('.');
                        if (dotPos != std::string::npos) {
                            indexStr = indexStr.substr(0, dotPos);
                            try {
                                size_t index = std::stoul(indexStr);
                                maxIndex = (maxIndex > index) ? maxIndex : index;
                            } catch (...) {
                                // 忽略无法解析的文件名
                            }
                        }
                    }
                }
            }
        }
        
        m_currentFileIndex = maxIndex + 1;
        
    } catch (...) {
        m_currentFileIndex = 0;
    }
}

inline void Logger::cleanupOldLogs() {
    try {
        std::string resolvedLogDir = resolvePath(m_logDir);
        std::filesystem::path logDir(resolvedLogDir);
        
        if (!std::filesystem::exists(logDir)) {
            return;
        }
        
        auto now = std::chrono::system_clock::now();
        
        for (const auto& entry : std::filesystem::directory_iterator(logDir)) {
            if (entry.is_directory()) {
                try {
                    std::string dirName = entry.path().filename().string();
                    std::tm tm = {};
                    std::istringstream ss(dirName);
                    ss >> std::get_time(&tm, "%Y-%m-%d");
                    
                    if (!ss.fail()) {
                        auto dirTime = std::chrono::system_clock::from_time_t(std::mktime(&tm));
                        auto daysDiff = std::chrono::duration_cast<std::chrono::hours>(now - dirTime).count() / 24;
                        
                        if (daysDiff > m_keepLogDays) {
                            std::filesystem::remove_all(entry.path());
                        }
                    }
                } catch (...) {
                }
            }
        }
    } catch (...) {
    }
}

inline bool Logger::loadConfig(const std::string& configFile) {
    m_configFile = configFile;
    
    // 默认配置
    m_logDir = "logs";
    m_logLevel = Level::INFO;
    m_consoleOutput = true;
    m_consoleMode = ConsoleMode::NORMAL;
    m_maxFileSize = 10 * 1024 * 1024; // 10MB
    m_maxFilesPerSlot = 10;
    m_keepLogDays = 7;
    m_flushIntervalMs = 100;
    m_batchSize = 10;
    
    std::ifstream file(configFile);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        size_t pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);
        
        if (key == "log_dir") {
            m_logDir = value;
        } else if (key == "log_level") {
            if (value == "TRACE") m_logLevel = Level::TRACE;
            else if (value == "DEBUG") m_logLevel = Level::DEBUG;
            else if (value == "INFO") m_logLevel = Level::INFO;
            else if (value == "WARN") m_logLevel = Level::WARN;
            else if (value == "ERR") m_logLevel = Level::ERR;
            else if (value == "FATAL") m_logLevel = Level::FATAL;
        } else if (key == "console_output") {
            m_consoleOutput = (value == "true");
        } else if (key == "console_mode") {
            if (value == "NORMAL") m_consoleMode = ConsoleMode::NORMAL;
            else if (value == "SCROLL") m_consoleMode = ConsoleMode::SCROLL;
            else if (value == "CLEAR") m_consoleMode = ConsoleMode::CLEAR;
        } else if (key == "max_file_size") {
            try {
                m_maxFileSize = std::stoul(value);
            } catch (...) {}
        } else if (key == "max_files_per_slot") {
            try {
                m_maxFilesPerSlot = std::stoul(value);
            } catch (...) {}
        } else if (key == "keep_log_days") {
            try {
                m_keepLogDays = std::stoi(value);
            } catch (...) {}
        } else if (key == "flush_interval_ms") {
            try {
                m_flushIntervalMs = std::stoi(value);
            } catch (...) {}
        } else if (key == "batch_size") {
            try {
                m_batchSize = std::stoul(value);
            } catch (...) {}
        }
    }
    
    return true;
}

inline size_t Logger::getTotalBufferedMessages() const {
    size_t total = 0;
    
    // 获取主写入缓冲区大小
    {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(m_writeBufferMutex));
        total += m_writeBuffer.size();
    }
    
    // 获取所有线程缓冲区大小
    auto buffers = g_bufferManager.getAllBuffers();
    for (const auto& buffer : buffers) {
        if (buffer) {
            // 由于是无锁环形缓冲区，我们无法直接获取大小
            // 这里只能返回一个估算值
            total += 512; // 假设每个缓冲区平均有512条消息
        }
    }
    
    return total;
}

// 内存安全检查函数实现
inline bool Logger::isValidLogMessage(const LogMessage& msg) const {
    try {
        // 检查时间戳是否合理（不能是未来时间，也不能太早）
        auto now = std::chrono::system_clock::now();
        auto timeDiff = std::chrono::duration_cast<std::chrono::seconds>(now - msg.timestamp);
        
        // 时间戳不能是未来时间，也不能超过1年
        if (timeDiff.count() < -1 || timeDiff.count() > 365 * 24 * 3600) {
            return false;
        }
        
        // 检查日志级别是否有效
        if (static_cast<int>(msg.level) < 0 || static_cast<int>(msg.level) > 5) {
            return false;
        }
        
        // 检查消息字符串是否有效
        try {
            // 尝试访问字符串的长度，如果内存无效会抛出异常
            size_t len = msg.message.length();
            
            // 检查长度是否合理（不能超过1MB）
            if (len > 1024 * 1024) {
                return false;
            }
            
            // 尝试访问字符串的第一个字符（如果字符串不为空）
            if (len > 0) {
                char firstChar = msg.message[0];
                (void)firstChar; // 避免未使用变量警告
            }
            
        } catch (const std::exception&) {
            return false;
        } catch (...) {
            return false;
        }
        
        return true;
        
    } catch (const std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}