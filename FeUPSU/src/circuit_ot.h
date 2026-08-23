#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace circuit {

struct PartyResult {
    std::vector<uint64_t> values;
    uint64_t comm_bytes = 0;
    uint64_t compute_ms = 0;
};

// Client is the OT sender.  For membership bit e = shc XOR shs, the server
// receives sx' when e=0 (client-only item) and sx when e=1 (dummy zero), since
// sx XOR sx is the all-zero dummy share.
PartyResult send_x_shares(const std::vector<uint64_t>& sx,
                          const std::vector<uint64_t>& sx_prime,
                          const std::vector<uint64_t>& shc,
                          const std::string& endpoint);

PartyResult receive_x_shares(const std::vector<uint64_t>& shs,
                             const std::string& endpoint);

} // namespace circuit
