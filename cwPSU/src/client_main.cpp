#include <getopt.h>
#include <omp.h>

#include <iostream>
#include <string>

#include "client.h"
#include "utils.h"

int main(int argc, char *argv[]) {
    omp_set_num_threads(32);
    uint64_t server_set = 1ULL << 20;
    uint64_t client_set = 0;
    uint64_t effective_bitlength = 32;
    uint64_t hw = 7;
    std::string host = "127.0.0.1";
    uint16_t port = 39002;

    static option options[] = {
        {"server-host", required_argument, nullptr, 'i'},
        {"server-port", required_argument, nullptr, 'p'},
        {"server_set", required_argument, nullptr, 's'},
        {"server-set", required_argument, nullptr, 's'},
        {"client_set", required_argument, nullptr, 'c'},
        {"client-set", required_argument, nullptr, 'c'},
        {"effective_bitlength", required_argument, nullptr, 'l'},
        {"effective-bitlength", required_argument, nullptr, 'l'},
        {"hamming_weight", required_argument, nullptr, 'h'},
        {"hamming-weight", required_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };
    int index = 0;
    for (int c; (c = getopt_long(argc, argv, "i:p:s:c:l:h:", options, &index)) != -1;) {
        switch (c) {
            case 'i': host = optarg; break;
            case 'p': port = static_cast<uint16_t>(std::stoul(optarg)); break;
            case 's': server_set = std::stoull(optarg); break;
            case 'c': client_set = std::stoull(optarg); break;
            case 'l': effective_bitlength = std::stoull(optarg); break;
            case 'h': hw = std::stoull(optarg); break;
            default: return 2;
        }
    }

    try {
        Params params(PSU, server_set, effective_bitlength, hw, client_set);
        Client client;
        client.set_server_endpoint(host, port);
        std::cout << "[cwPSU client] server=" << host << ':' << port
                  << " server_set=" << server_set
                  << " client_set=" << (client_set ? client_set : 1ULL << params.log_poly_modulus_degree)
                  << " effective_bitlength=" << effective_bitlength
                  << " hw=" << hw << std::endl;
        return client.run_protocol(params, false) ? 0 : 1;
    } catch (const std::exception &error) {
        std::cerr << "[cwPSU client][FATAL] " << error.what() << std::endl;
        return 1;
    }
}
