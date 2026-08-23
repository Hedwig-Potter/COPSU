#include <getopt.h>
#include <omp.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

#include "server.h"
#include "utils.h"

namespace {
std::atomic<bool> running{true};
void handle_signal(int) { running.store(false); }
}

int main(int argc, char* argv[]) {
    omp_set_num_threads(32);
    uint16_t psu_port = 39002;

    static option options[] = {
        {"port", required_argument, nullptr, 'p'},
        {nullptr, 0, nullptr, 0}
    };
    int option_index = 0;
    int c = 0;
    while ((c = getopt_long(argc, argv, "p:", options, &option_index)) != -1) {
        if (c == 'p') psu_port = static_cast<uint16_t>(std::stoul(optarg));
        else return 2;
    }
    if (psu_port != 39002) {
        std::cerr << "[Server][FATAL] non-default PSU port is not yet configurable in NetworkConfig" << std::endl;
        return 2;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    try {
        Server server;
        Metrics metrics;
        Params placeholder;
        server.start_psu_service(placeholder, 0, &metrics, false);
        server.start_masked_service();
        server.start_circuit_service();
        server.start_psuca_mid_service();
        std::cout << "[Server] PSU, masked, cardinality, and circuit services started" << std::endl;

        while (running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        server.stop_psu_service();
        server.stop_masked_service();
        server.stop_circuit_service();
        server.stop_psuca_mid_service();
    } catch (const std::exception& ex) {
        std::cerr << "[Server][FATAL] " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}
