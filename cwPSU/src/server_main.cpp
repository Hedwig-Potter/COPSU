#include <getopt.h>
#include <omp.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <thread>

#include "server.h"
#include "utils.h"

namespace {
std::atomic<bool> running{true};
void handle_signal(int) { running.store(false); }
}

int main(int argc, char *argv[]) {
    omp_set_num_threads(32);
    uint16_t port = 39002;
    static option options[] = {{"port", required_argument, nullptr, 'p'}, {nullptr, 0, nullptr, 0}};
    int index = 0;
    for (int c; (c = getopt_long(argc, argv, "p:", options, &index)) != -1;) {
        if (c == 'p') port = static_cast<uint16_t>(std::stoul(optarg));
        else return 2;
    }
    if (port != 39002) {
        const std::string value = std::to_string(port);
        setenv("PSU_SERVER_PORT", value.c_str(), 1);
    }
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    try {
        Server server;
        Metrics metrics;
        Params placeholder;
        server.start_psu_service(placeholder, 0, &metrics, false);
        server.start_masked_service();
        std::cout << "[cwPSU server] PSU port " << port << ", masked port "
                  << (std::getenv("PSU_MASKED_PORT") ? std::getenv("PSU_MASKED_PORT") : "39003")
                  << std::endl;
        while (running.load()) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        server.stop_psu_service();
        server.stop_masked_service();
    } catch (const std::exception &error) {
        std::cerr << "[cwPSU server][FATAL] " << error.what() << std::endl;
        return 1;
    }
    return 0;
}
