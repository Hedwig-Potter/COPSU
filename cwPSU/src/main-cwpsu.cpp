#include <iostream>
#include <cmath>
#include <getopt.h>
#include <string>
#include "utils.h"
#include "client.h"
#include "server.h"

using namespace std;

int main(int argc, char* argv[]) {
    cout << "cwPSU entry" << endl;
    omp_set_num_threads(32);

    // Defaults; adjust as needed for cwPSU
    uint64_t effective_bitlength = 32;
    uint64_t hw = 7;
    uint64_t client_set = 0;
    uint64_t server_set = 1 << 20;
    // uint64_t N = 8192;
    // uint64_t mu = 1;
    // uint64_t num_bins = 1;
    // uint64_t num_balls = 1;

    // num_bins = N ;
    // num_balls = 3 * server_set;
    // mu = ceil((float)num_balls / num_bins + 2 * sqrt((float)num_balls * log2(num_bins) / num_bins));

    Task task = PSU;

    static struct option long_options[] = {
        {"client_set", required_argument, nullptr, 'c'},
        {"server_set", required_argument, nullptr, 's'},
        {"effective_bitlength", required_argument, nullptr, 'l'},
        {"hamming_weight", required_argument, nullptr, 'h'},
        {"task", required_argument, nullptr, 't'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;
    while ((c = getopt_long(argc, argv, "c:s:l:h:t:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'c':
                if (optarg) client_set = strtoull(optarg, nullptr, 10);
                break;
            case 's':
                if (optarg) server_set = strtoull(optarg, nullptr, 10);
                break;
            case 'l':
                if (optarg) effective_bitlength = strtoull(optarg, nullptr, 10);
                break;
            case 'h':
                if (optarg) hw = strtoull(optarg, nullptr, 10);
                break;
            case 't':
                if (optarg) {
                    string task_str(optarg);
                    if (task_str == "PSU") task = PSU;
                    else if (task_str == "PSUCardinality") task = PSUCardinality;
                    else if (task_str == "circuitPSU") task = circuitPSU;
                    else {
                        cerr << "[WARN] Unrecognized task '" << task_str << "'，keeping the default PSU" << endl;
                        task = PSU;
                    }
                }
                break;
            default:
                std::abort();
        }
    }

    
    cout << "--- cwPSU Specs ---" << endl;
    cout << "Client set size: " << (client_set == 0 ? string("default bin_count") : to_string(client_set)) << endl;
    cout << "Server set size: " << server_set << endl;
    cout << "Effective bitlength: " << effective_bitlength << endl;
    cout << "Hamming weight: " << hw << endl;

    Server* server = new Server();
    Client client(server);

    Params params(task, server_set, effective_bitlength, hw, client_set);
    client.run_protocol(params);
}