#pragma once
#include <vector>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <memory>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdexcept>
#include <iostream>

namespace psu::network {

class ScopedFd {
    int fd_ = -1;
public:
    explicit ScopedFd(int fd = -1) : fd_(fd) {}
    ~ScopedFd() { reset(); }
    
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
    
    ScopedFd(ScopedFd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    ScopedFd& operator=(ScopedFd&& other) noexcept {
        if (this != &other) { reset(); fd_ = other.fd_; other.fd_ = -1; }
        return *this;
    }

    int get() const { return fd_; }
    void reset(int new_fd = -1) {
        if (fd_ >= 0) ::close(fd_);
        fd_ = new_fd;
    }
    bool is_valid() const { return fd_ >= 0; }
};

class SocketUtils {
public:
    static bool send_all(int fd, const void* data, size_t len) {
        const char* ptr = static_cast<const char*>(data);
        while (len > 0) {
            ssize_t sent = ::send(fd, ptr, len, 0);
            if (sent <= 0) return false;
            ptr += sent;
            len -= sent;
        }
        return true;
    }

    static bool recv_all(int fd, void* data, size_t len) {
        char* ptr = static_cast<char*>(data);
        while (len > 0) {
            ssize_t recvd = ::recv(fd, ptr, len, 0);
            if (recvd <= 0) return false;
            ptr += recvd;
            len -= recvd;
        }
        return true;
    }

    static bool send_message(int fd, const std::vector<uint8_t>& msg) {
        uint32_t length = htonl(static_cast<uint32_t>(msg.size()));
        if (!send_all(fd, &length, sizeof(length))) return false;
        if (!msg.empty() && !send_all(fd, msg.data(), msg.size())) return false;
        return true;
    }

    static bool recv_message(int fd, std::vector<uint8_t>& msg) {
        uint32_t length = 0;
        if (!recv_all(fd, &length, sizeof(length))) return false;
        length = ntohl(length);
        msg.resize(length);
        if (length > 0 && !recv_all(fd, msg.data(), length)) return false;
        return true;
    }
};

class SocketServer {
public:
    using ClientHandler = std::function<void(int client_fd)>;

    SocketServer(uint16_t port, ClientHandler handler)
        : port_(port), handler_(std::move(handler)) {}

    ~SocketServer() { stop(); }

    void start() {
        int raw_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (raw_fd < 0) throw std::runtime_error("Failed to create server socket");
        server_fd_.reset(raw_fd);

        int opt = 1;
        ::setsockopt(server_fd_.get(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port_);

        if (::bind(server_fd_.get(), (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            throw std::runtime_error("Failed to bind port " + std::to_string(port_));
        }

        if (::listen(server_fd_.get(), 10) < 0) {
            throw std::runtime_error("Listen failed");
        }

        running_ = true;
        accept_thread_ = std::thread(&SocketServer::accept_loop, this);
    }

    void stop() {
        if (running_) {
            running_ = false;
            // close() from another thread does not reliably interrupt accept()
            // on Linux.  Wake it with a loopback connection before joining.
            int wake_fd = ::socket(AF_INET, SOCK_STREAM, 0);
            if (wake_fd >= 0) {
                sockaddr_in wake_addr{};
                wake_addr.sin_family = AF_INET;
                wake_addr.sin_port = htons(port_);
                ::inet_pton(AF_INET, "127.0.0.1", &wake_addr.sin_addr);
                ::connect(wake_fd, reinterpret_cast<sockaddr*>(&wake_addr), sizeof(wake_addr));
                ::close(wake_fd);
            }
            if (accept_thread_.joinable()) {
                accept_thread_.join();
            }
            server_fd_.reset();
        }
    }

private:
    void accept_loop() {
        while (running_) {
            sockaddr_in client_addr{};
            socklen_t addr_len = sizeof(client_addr);
            int client_raw_fd = ::accept(server_fd_.get(), (struct sockaddr*)&client_addr, &addr_len);
            if (client_raw_fd < 0) {
                if (!running_) break;
                continue;
            }
            if (!running_) {
                ::close(client_raw_fd);
                break;
            }

            std::thread([this, client_raw_fd]() {
                ScopedFd client_fd(client_raw_fd);
                try {
                    if (handler_) {
                        handler_(client_fd.get());
                    }
                } catch (const std::exception& ex) {
                    std::cerr << "[ERROR] SocketServer handler on port " << port_
                              << " failed: " << ex.what() << std::endl;
                } catch (...) {
                    std::cerr << "[ERROR] SocketServer handler on port " << port_
                              << " failed with an unknown exception" << std::endl;
                }
            }).detach();
        }
    }

    uint16_t port_;
    ClientHandler handler_;
    ScopedFd server_fd_;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
};

class SocketClient {
public:
    static ScopedFd connect_to(const std::string& ip, uint16_t port) {
        int raw_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (raw_fd < 0) throw std::runtime_error("Socket creation failed");
        ScopedFd client_fd(raw_fd);

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        if (::inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
            throw std::runtime_error("Invalid IP address");
        }

        if (::connect(client_fd.get(), (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            throw std::runtime_error("Connection failed to " + ip + ":" + std::to_string(port));
        }

        return client_fd;
    }
};

} // namespace psu::network
