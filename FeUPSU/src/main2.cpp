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

    static struct option long_options[] = {
        {"server_set", optional_argument, 0, 's'},
        {"task", optional_argument, 0, 't'},
        {"effective_bitlength", optional_argument, 0, 'l'},
        {"hamming_weight", optional_argument, 0, 'h'},
        {"time_OTSSS", no_argument, 0, 'o'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;

    while ((c = getopt_long(argc, argv, "s:t:l:h:o", long_options, &option_index)) != -1) {
        switch (c) {
            case 's':
                if (optarg) {
                    server_set = strtoull(optarg, nullptr, 10);
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
                        cerr << "[WARN] 未识别的任务类型 '" << val << "'，默认使用 PSU" << endl;
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
            case '?':
                // getopt_long already printed the error
                return 1;
            default:
                std::abort();
        }
    }

    Server* server = new Server();
    Client client(server);

    Params params(task, server_set, effective_bitlength, hw);
    params.time_otsss = time_otsss;
    client.run_protocol(params);

}