#include <iostream>
#include <getopt.h>
#include "utils.h"
#include "client.h"
#include "server.h"

using namespace std;

int main(int argc, char * argv[]) {
    omp_set_num_threads(32);

    uint64_t effective_bitlength = 32;
    uint64_t server_set = 1ULL << 20;
    uint64_t hw = 4;
    uint64_t client_set = 0;

    Task task = PSU;
    bool time_otsss = false;

    static struct option long_options[] = {
        {"server_set", required_argument, nullptr, 's'},
        {"client_set", required_argument, nullptr, 'c'},
        {"effective_bitlength", required_argument, nullptr, 'l'},
        {"hamming_weight", required_argument, nullptr, 'h'},
        {"task", required_argument, nullptr, 't'},
        {"time_OTSSS", no_argument, nullptr, 'o'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;
    while ((c = getopt_long(argc, argv, "s:c:l:h:t:o", long_options, &option_index)) != -1) {
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
            case 't':
                if (optarg) {
                    string task_str(optarg);
                    if (task_str == "PSU") task = PSU;
                    else if (task_str == "PSUca_C") task = PSUca_C;
                    else if (task_str == "PSUca_S") task = PSUca_S;
                    else if (task_str == "PSUCardinality") task = PSUca_C;
                    else if (task_str == "circuitPSU") task = circuitPSU;
                    else {
                        cerr << "[WARN] Unrecognized task '" << task_str << "'，using the default PSU" << endl;
                        task = PSU;
                    }
                }
                break;
            case 'o':
                time_otsss = true;
                break;
            default:
                break;
        }
    }

    Server* server = new Server();
    Client client(server);

    // vector<uint64_t> best_comm_hw({
    //     8, 8, 12, 13, 13, 14, 15, 15, 16, 16, 15, 15, 16, 16,
    //     // ...
    // });
    // vector<uint64_t> best_comp_hw({
    //     4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 6,
    //     // ...
    // });

    Params params(task, server_set, effective_bitlength, hw, client_set);
    params.time_otsss = time_otsss;
    client.run_protocol(params);

}