#include <getopt.h>
#include <omp.h>

#include <cstdlib>
#include <iostream>
#include <string>

#include "client.h"
#include "utils.h"

int main(int argc, char* argv[]) {
    omp_set_num_threads(32);

    uint64_t server_set = 1ULL << 20;
    uint64_t client_set = 0;
    uint64_t effective_bitlength = 32;
    uint64_t hw = 4;
    std::string server_host = "127.0.0.1";
    uint16_t server_port = 39002;
    Task task = PSU;

    static option options[] = {
        {"server-host", required_argument, nullptr, 'i'},
        {"server-port", required_argument, nullptr, 'p'},
        {"server-set", required_argument, nullptr, 's'},
        {"server_set", required_argument, nullptr, 's'},
        {"client-set", required_argument, nullptr, 'c'},
        {"client_set", required_argument, nullptr, 'c'},
        {"effective-bitlength", required_argument, nullptr, 'l'},
        {"effective_bitlength", required_argument, nullptr, 'l'},
        {"hamming-weight", required_argument, nullptr, 'h'},
        {"hamming_weight", required_argument, nullptr, 'h'},
        {"task", required_argument, nullptr, 't'},
        {nullptr, 0, nullptr, 0}
    };

    int option_index = 0;
    int c = 0;
    while ((c = getopt_long(argc, argv, "i:p:s:c:l:h:t:", options, &option_index)) != -1) {
        switch (c) {
            case 'i': server_host = optarg; break;
            case 'p': server_port = static_cast<uint16_t>(std::stoul(optarg)); break;
            case 's': server_set = std::stoull(optarg); break;
            case 'c': client_set = std::stoull(optarg); break;
            case 'l': effective_bitlength = std::stoull(optarg); break;
            case 'h': hw = std::stoull(optarg); break;
            case 't': {
                std::string value(optarg);
                if (value == "PSU") task = PSU;
                else if (value == "PSUca_C") task = PSUca_C;
                else if (value == "PSUca_S") task = PSUca_S;
                else if (value == "circuitPSU") task = circuitPSU;
                else throw std::invalid_argument("--task must be PSU, PSUca_C, PSUca_S, or circuitPSU");
                break;
            }
            default: return 2;
        }
    }

    try {
        Params params(task, server_set, effective_bitlength, hw, client_set);
        Client client;
        client.set_server_endpoint(server_host, server_port);
        std::cout << "[Client] server=" << server_host << ':' << server_port
                  << " server_set=" << server_set
                  << " client_set=" << (client_set ? client_set : (1ULL << params.log_poly_modulus_degree))
                  << " logN=" << params.log_poly_modulus_degree
                  << " effective_bitlength=" << effective_bitlength
                  << " hw=" << hw << std::endl;
        return client.run_protocol(params, true) ? 0 : 1;
    } catch (const std::exception& ex) {
        std::cerr << "[Client][FATAL] " << ex.what() << std::endl;
        return 1;
    }
}
