#include <iostream>
#include <getopt.h>
#include "utils.h"
#include "client.h"
#include "server.h"

using namespace std;


/*
    This code takes in the effective bitlength and hamming weight.
    mu and gamma and b_0 is fixed
    This function can be used to optimize protocol.
    This can be done by iterating over different Hamming weights and observing the comm. and comp.
*/

// main function with arguements
int main(int argc, char* argv[]) {
    cout << "Hello World!" << endl; 
    
    // The number of threads is set to 1 to be able to optimize the communication cost without noise
    omp_set_num_threads(1);

    // These don't matter for this experiement
    uint64_t server_set = 3;
    // uint64_t gamma = 1;
    Task task = PSU;
    bool time_otsss = false;

    // These two will vary
    uint64_t effective_bitlength = 19;
    uint64_t hw=8;
    uint64_t client_set = 0;
    uint64_t plain_modulus_bits = 20;

    static struct option long_options[] = {
        {"server_set", required_argument, 0, 's'},
        {"client_set", required_argument, 0, 'c'},
        {"task", required_argument, 0, 't'},
        {"effective_bitlength", required_argument, 0, 'l'},
        {"hamming_weight", required_argument, 0, 'h'},
        {"time_OTSSS", no_argument, 0, 'o'},
        {"plain_modulus_bits", required_argument, 0, 'p'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;

    while ((c = getopt_long(argc, argv, "s:c:t:l:h:op:", long_options, &option_index)) != -1) {
        switch (c) {
            case 's':
                if (optarg) {
                    server_set = strtoull(optarg, nullptr, 10);
                }
                break;
            case 'c':
                if (optarg) {
                    client_set = strtoull(optarg, nullptr, 10);
                }
                break;
            case 't':
                if (optarg) {
                    string val(optarg);
                    if (val == "PSU") {
                        task = PSU;
                    } else if (val == "PSUca_C") {
                        task = PSUca_C;
                    } else if (val == "PSUca_S") {
                        task = PSUca_S;
                    } else if (val == "PSUCardinality") {
                        task = PSUca_C;
                    } else if (val == "circuitPSU") {
                        task = circuitPSU;
                    } else {
                        cerr << "[WARN] Unrecognized task '" << val << "'，using PSU by default" << endl;
                        task = PSU;
                    }
                }
                break;
            case 'l':
                if (optarg) {
                    effective_bitlength = strtoull(optarg, nullptr, 10);
                }
                break;
            case 'h':
                if (optarg) {
                    hw = strtoull(optarg, nullptr, 10);
                }
                break;
            case 'o':
                time_otsss = true;
                break;
            case 'p':
                if (optarg) plain_modulus_bits = strtoull(optarg, nullptr, 10);
                break;
            case '?':
                // getopt_long already printed the error
                return 1;
            default:
                std::abort();
        }
    }

    Server* server = new Server();
    Client client(server);

    Params params(task, server_set, effective_bitlength, hw, client_set);
    // The hw-search experiment uses a fixed BFV plaintext modulus. This is
    // independent of the original element length and the CW-code capacity.
    params.prime_bitlength = plain_modulus_bits;
    params.time_otsss = time_otsss;
    client.run_protocol(params);

}
