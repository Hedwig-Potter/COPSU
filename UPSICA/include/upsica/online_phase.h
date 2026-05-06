#pragma once

#include <cstdint>
#include <vector>

#include "upsica/preparation_phase.h"

namespace upsica::protocol {

struct OnlineOutput {
    uint64_t intersection_cardinality = 0;
    std::vector<uint64_t> receiver_oprf_values;
    std::vector<uint64_t> matched_oprf_values;
    bool used_fhe_online = false;
    bool used_polynomial_links = false;
    bool used_cuckoo_hashing = false;
    bool used_sender_simple_hashing = false;
    uint64_t bin_count = 0;
    uint64_t alpha_sub_bins = 0;
    uint64_t cuckoo_items_placed = 0;
    uint64_t cuckoo_items_dropped = 0;
    uint64_t encrypted_query_slices = 0;
    uint64_t sender_evaluated_slices = 0;
    uint64_t returned_ciphertexts = 0;
};

OnlineOutput RunOnline(const std::vector<uint64_t>& receiver_set, const PreparationOutput& prep_output);

}  // namespace upsica::protocol
