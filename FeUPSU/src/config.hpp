#pragma once
#include <string>
#include <cstdint>
#include <cstdlib>

namespace psu::config {

struct NetworkConfig {
    std::string server_ip = "127.0.0.1";
    std::string host = server_ip;
    uint16_t psu_server_port = 39002;
    uint16_t psu_port = psu_server_port;
    uint16_t masked_port     = 39003;
    uint16_t ca_mid_port     = 39006;
    uint16_t syprime_port    = 39005;
    uint16_t permute_port    = 39006;
    uint16_t permute_share_port = permute_port;
    uint16_t circuit_control_port = 39007;
    uint16_t circuit_ot_port = 39008;
    uint16_t circuit_osn_port = 39009;

    NetworkConfig() {
        const char* value = std::getenv("FEUPSU_PORT_BASE");
        if (!value || !*value) return;
        char* end = nullptr;
        long base = std::strtol(value, &end, 10);
        if (!end || *end != '\0' || base <= 0 || base > 65528) return;
        psu_server_port = psu_port = static_cast<uint16_t>(base);
        masked_port = static_cast<uint16_t>(base + 1);
        ca_mid_port = static_cast<uint16_t>(base + 4);
        syprime_port = static_cast<uint16_t>(base + 3);
        permute_port = permute_share_port = static_cast<uint16_t>(base + 4);
        circuit_control_port = static_cast<uint16_t>(base + 5);
        circuit_ot_port = static_cast<uint16_t>(base + 6);
        circuit_osn_port = static_cast<uint16_t>(base + 7);
    }
};

struct ProtocolParams {
    uint32_t log_poly_modulus_degree = 12; // N = 4096
    uint64_t client_set_size         = 1000;
    uint64_t server_set_size         = 4096;
    
    size_t ell                      = 32;
    size_t hw                       = 4;
    size_t effective_lambda         = 40;
    size_t share_pad_bits           = 10;
};

} // namespace psu::config
