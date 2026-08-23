#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "upsica/vbf_psi_ca.h"
#include <seal/seal.h>

namespace {
using Clock = std::chrono::steady_clock;
using upsica::crypto::Ciphertext;
using upsica::crypto::OprfMessage;
using upsica::protocol::EncryptedVbfQuery;
using upsica::protocol::EncryptedVbfResponse;

enum class MessageType : uint32_t { OprfRequest = 1, OprfResponse = 2, FheQuery = 3, FheResponse = 4 };

struct Writer {
    std::vector<uint8_t> data;
    template <typename T> void pod(const T& value) {
        static_assert(std::is_trivially_copyable_v<T>);
        const auto* p = reinterpret_cast<const uint8_t*>(&value);
        data.insert(data.end(), p, p + sizeof(T));
    }
    void bytes(const std::vector<uint8_t>& value) {
        pod<uint64_t>(value.size());
        data.insert(data.end(), value.begin(), value.end());
    }
};

struct Reader {
    const std::vector<uint8_t>& data;
    size_t offset = 0;
    template <typename T> T pod() {
        if (offset + sizeof(T) > data.size()) throw std::runtime_error("truncated message");
        T value;
        std::memcpy(&value, data.data() + offset, sizeof(T));
        offset += sizeof(T);
        return value;
    }
    std::vector<uint8_t> bytes() {
        uint64_t size = pod<uint64_t>();
        if (offset + size > data.size()) throw std::runtime_error("truncated byte vector");
        std::vector<uint8_t> value(data.begin() + offset, data.begin() + offset + size);
        offset += size;
        return value;
    }
};

bool writeAll(int fd, const void* input, size_t size) {
    const auto* p = static_cast<const uint8_t*>(input);
    while (size) {
        ssize_t written = send(fd, p, size, MSG_NOSIGNAL);
        if (written <= 0) return false;
        p += written;
        size -= static_cast<size_t>(written);
    }
    return true;
}

bool readAll(int fd, void* output, size_t size) {
    auto* p = static_cast<uint8_t*>(output);
    while (size) {
        ssize_t received = recv(fd, p, size, 0);
        if (received <= 0) return false;
        p += received;
        size -= static_cast<size_t>(received);
    }
    return true;
}

uint64_t sendFrame(int fd, MessageType type, const std::vector<uint8_t>& payload) {
    uint32_t wire_type = static_cast<uint32_t>(type);
    uint64_t length = payload.size();
    if (!writeAll(fd, &wire_type, sizeof(wire_type)) ||
        !writeAll(fd, &length, sizeof(length)) ||
        (!payload.empty() && !writeAll(fd, payload.data(), payload.size()))) {
        throw std::runtime_error("socket send failed");
    }
    return sizeof(wire_type) + sizeof(length) + length;
}

std::pair<MessageType, std::vector<uint8_t>> receiveFrame(int fd, uint64_t& wire_bytes) {
    uint32_t type = 0;
    uint64_t length = 0;
    if (!readAll(fd, &type, sizeof(type)) || !readAll(fd, &length, sizeof(length))) {
        throw std::runtime_error("socket receive header failed");
    }
    if (length > (uint64_t{1} << 40)) throw std::runtime_error("unreasonable frame length");
    std::vector<uint8_t> payload(length);
    if (length && !readAll(fd, payload.data(), payload.size())) {
        throw std::runtime_error("socket receive payload failed");
    }
    wire_bytes = sizeof(type) + sizeof(length) + length;
    return {static_cast<MessageType>(type), std::move(payload)};
}

std::vector<uint8_t> serializeOprf(const std::vector<OprfMessage>& messages) {
    Writer w;
    w.pod<uint64_t>(messages.size());
    for (const auto& message : messages) w.bytes(message.payload);
    return std::move(w.data);
}

std::vector<OprfMessage> deserializeOprf(const std::vector<uint8_t>& payload) {
    Reader r{payload};
    uint64_t count = r.pod<uint64_t>();
    std::vector<OprfMessage> messages(count);
    for (auto& message : messages) message.payload = r.bytes();
    return messages;
}

std::vector<uint8_t> serializeQuery(const EncryptedVbfQuery& query) {
    Writer w;
    w.bytes(query.evaluation_keys.public_key);
    w.bytes(query.evaluation_keys.relin_keys);
    w.pod(query.slot_count);
    w.pod(query.chunk_count);
    w.pod(query.maximum_power);
    w.pod(query.slice_count);
    for (uint32_t s = 0; s < query.slice_count; ++s)
        for (uint32_t c = 0; c < query.chunk_count; ++c)
            for (uint32_t p = 0; p < query.maximum_power; ++p)
                w.bytes(query.encrypted_powers[s][c][p].data);
    return std::move(w.data);
}

EncryptedVbfQuery deserializeQuery(const std::vector<uint8_t>& payload) {
    Reader r{payload};
    EncryptedVbfQuery query;
    query.evaluation_keys.public_key = r.bytes();
    query.evaluation_keys.relin_keys = r.bytes();
    query.slot_count = r.pod<uint32_t>();
    query.chunk_count = r.pod<uint32_t>();
    query.maximum_power = r.pod<uint32_t>();
    query.slice_count = r.pod<uint32_t>();
    query.encrypted_powers.resize(query.slice_count);
    for (uint32_t s = 0; s < query.slice_count; ++s) {
        query.encrypted_powers[s].resize(query.chunk_count);
        for (uint32_t c = 0; c < query.chunk_count; ++c) {
            query.encrypted_powers[s][c].resize(query.maximum_power);
            for (auto& ciphertext : query.encrypted_powers[s][c]) ciphertext.data = r.bytes();
        }
    }
    return query;
}

std::vector<uint8_t> serializeResponse(const EncryptedVbfResponse& response) {
    Writer w;
    w.pod(response.chunk_count);
    w.pod(response.slice_count);
    w.pod(response.alpha_sub_bins);
    for (uint32_t sb = 0; sb < response.alpha_sub_bins; ++sb)
        for (uint32_t s = 0; s < response.slice_count; ++s)
            for (uint32_t c = 0; c < response.chunk_count; ++c)
                w.bytes(response.evaluations[sb][s][c].data);
    return std::move(w.data);
}

EncryptedVbfResponse deserializeResponse(const std::vector<uint8_t>& payload) {
    Reader r{payload};
    EncryptedVbfResponse response;
    response.chunk_count = r.pod<uint32_t>();
    response.slice_count = r.pod<uint32_t>();
    response.alpha_sub_bins = r.pod<uint32_t>();
    response.evaluations.resize(response.alpha_sub_bins);
    for (uint32_t sb = 0; sb < response.alpha_sub_bins; ++sb) {
        response.evaluations[sb].resize(response.slice_count);
        for (uint32_t s = 0; s < response.slice_count; ++s) {
            response.evaluations[sb][s].resize(response.chunk_count);
            for (auto& ciphertext : response.evaluations[sb][s]) ciphertext.data = r.bytes();
        }
    }
    return response;
}

upsica::protocol::ItemBytes makeItem(uint64_t value, uint32_t bits) {
    size_t bytes = (bits + 7) / 8;
    upsica::protocol::ItemBytes item(bytes, 0);
    for (size_t i = 0; i < std::min<size_t>(bytes, sizeof(value)); ++i)
        item[i] = static_cast<uint8_t>(value >> (8 * i));
    return item;
}

std::vector<upsica::protocol::ItemBytes> senderSet(uint64_t size, uint32_t bits) {
    std::vector<upsica::protocol::ItemBytes> set;
    set.reserve(size);
    for (uint64_t i = 0; i < size; ++i) set.push_back(makeItem(i + 1, bits));
    return set;
}

std::vector<upsica::protocol::ItemBytes> receiverSet(uint64_t size, uint64_t intersection,
                                                     uint64_t sender_size, uint32_t bits) {
    std::vector<upsica::protocol::ItemBytes> set;
    set.reserve(size);
    for (uint64_t i = 0; i < std::min(size, intersection); ++i)
        set.push_back(makeItem(i + 1, bits));
    for (uint64_t i = intersection; i < size; ++i)
        set.push_back(makeItem(sender_size + (i - intersection) + 1, bits));
    return set;
}

struct Options {
    std::string role;
    std::string host = "127.0.0.1";
    uint16_t port = 19090;
    uint64_t sender_size = 1 << 18;
    uint64_t receiver_size = 1024;
    uint64_t intersection = 16;
    uint32_t element_bits = 32;
    std::string results;
    upsica::protocol::VbfPsiCaConfig config;
};

Options parseOptions(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        std::string key = argv[i];
        auto value = [&]() -> std::string {
            if (++i >= argc) throw std::invalid_argument("missing value for " + key);
            return argv[i];
        };
        if (key == "--role") options.role = value();
        else if (key == "--host") options.host = value();
        else if (key == "--port") options.port = static_cast<uint16_t>(std::stoul(value()));
        else if (key == "--sender-set") options.sender_size = std::stoull(value());
        else if (key == "--receiver-set") options.receiver_size = std::stoull(value());
        else if (key == "--intersection") options.intersection = std::stoull(value());
        else if (key == "--element-bits") options.element_bits = std::stoul(value());
        else if (key == "--results") options.results = value();
        else if (key == "--bins") options.config.bin_count = std::stoul(value());
        else if (key == "--alpha") options.config.alpha_sub_bins = std::stoul(value());
        else if (key == "--kv") options.config.kv = std::stoul(value());
        else if (key == "--vbf-bits") options.config.vbf_item_bits = std::stoul(value());
        else if (key == "--slice-bits") options.config.slice_bits = std::stoul(value());
        else if (key == "--poly-degree") options.config.poly_modulus_degree = std::stoul(value());
        else if (key == "--plain-bits") options.config.plain_modulus_bits = std::stoul(value());
        else throw std::invalid_argument("unknown option: " + key);
    }
    if (options.role != "server" && options.role != "client")
        throw std::invalid_argument("--role must be server or client");
    if (options.element_bits != 32 && options.element_bits != 128)
        throw std::invalid_argument("--element-bits must be 32 or 128");
    if (options.element_bits == 32 &&
        options.sender_size + options.receiver_size -
            std::min(options.intersection, options.receiver_size) > (uint64_t{1} << 32))
        throw std::invalid_argument("32-bit test universe is too small for disjoint generated sets");
    return options;
}

int listenAndAccept(uint16_t port) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) throw std::runtime_error("socket failed");
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
        listen(listen_fd, 1)) {
        close(listen_fd);
        throw std::runtime_error("bind/listen failed");
    }
    int fd = accept(listen_fd, nullptr, nullptr);
    close(listen_fd);
    if (fd < 0) throw std::runtime_error("accept failed");
    return fd;
}

int connectRetry(const std::string& host, uint16_t port) {
    for (int attempt = 0; attempt < 300; ++attempt) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1)
            throw std::invalid_argument("host must be an IPv4 address");
        if (connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0) return fd;
        close(fd);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    throw std::runtime_error("unable to connect to server");
}

void writeMetrics(const std::string& path,
                  const std::vector<std::pair<std::string, std::string>>& metrics) {
    if (path.empty()) return;
    std::filesystem::path output(path);
    if (!output.parent_path().empty()) std::filesystem::create_directories(output.parent_path());
    std::ofstream stream(path);
    if (!stream) throw std::runtime_error("failed to open results file");
    for (const auto& [key, value] : metrics) stream << key << ',' << value << '\n';
}

double milliseconds(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

void runServer(const Options& options) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) throw std::runtime_error("socket failed");
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(options.port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
        listen(listen_fd, 1)) throw std::runtime_error("bind/listen failed");

    auto offline_start = Clock::now();
    auto preparation = upsica::protocol::PrepareVbfPsiCaSender(
        senderSet(options.sender_size, options.element_bits), options.config);
    auto offline_end = Clock::now();
    int fd = accept(listen_fd, nullptr, nullptr);
    close(listen_fd);
    if (fd < 0) throw std::runtime_error("accept failed");

    uint64_t received = 0;
    auto [oprf_type, oprf_payload] = receiveFrame(fd, received);
    if (oprf_type != MessageType::OprfRequest) throw std::runtime_error("expected OPRF request");
    auto online_start = Clock::now();
    auto oprf_start = Clock::now();
    auto oprf_response = upsica::protocol::EvaluateReceiverOprfBatch(
        preparation, deserializeOprf(oprf_payload));
    auto oprf_end = Clock::now();
    uint64_t sent = sendFrame(fd, MessageType::OprfResponse, serializeOprf(oprf_response));

    uint64_t query_bytes = 0;
    auto [query_type, query_payload] = receiveFrame(fd, query_bytes);
    if (query_type != MessageType::FheQuery) throw std::runtime_error("expected FHE query");
    auto fhe_start = Clock::now();
    auto response = upsica::protocol::EvaluateEncryptedVbfQuery(
        preparation, deserializeQuery(query_payload));
    auto fhe_end = Clock::now();
    uint64_t response_bytes = sendFrame(fd, MessageType::FheResponse,
                                        serializeResponse(response));
    auto online_end = Clock::now();
    close(fd);

    writeMetrics(options.results, {
        {"role", "server"}, {"sender_set", std::to_string(options.sender_size)},
        {"element_bits", std::to_string(options.element_bits)},
        {"time_setup_server_oprf_keygen", std::to_string(preparation.oprf_keygen_ms)},
        {"time_offline_comp", std::to_string(
            std::max(0.0, milliseconds(offline_start, offline_end) - preparation.oprf_keygen_ms))},
        {"time_online_comp_and_send", std::to_string(milliseconds(online_start, online_end))},
        {"time_online_server_oprf_comp", std::to_string(milliseconds(oprf_start, oprf_end))},
        {"time_online_server_fhe_comp", std::to_string(milliseconds(fhe_start, fhe_end))},
        {"comm_online_received", std::to_string(received + query_bytes)},
        {"comm_online_sent", std::to_string(sent + response_bytes)},
        {"maximum_sub_bin_degree", std::to_string(preparation.maximum_sub_bin_degree)}
    });
}

void runClient(const Options& options) {
    auto set = receiverSet(options.receiver_size, options.intersection,
                           options.sender_size, options.element_bits);
    auto online_wall_start = Clock::now();
    auto oprf_compute_start = Clock::now();
    auto batch = upsica::protocol::CreateReceiverOprfBatch(set);
    auto oprf_compute_end = Clock::now();
    int fd = connectRetry(options.host, options.port);
    uint64_t upload = sendFrame(fd, MessageType::OprfRequest, serializeOprf(batch.blinded_inputs));
    uint64_t download = 0;
    auto [oprf_type, oprf_payload] = receiveFrame(fd, download);
    if (oprf_type != MessageType::OprfResponse) throw std::runtime_error("expected OPRF response");

    auto setup_start = Clock::now();
    upsica::crypto::FheWrapper receiver_fhe(
        {options.config.poly_modulus_degree, options.config.plain_modulus_bits});
    receiver_fhe.Initialize();
    auto setup_end = Clock::now();
    auto query_compute_start = Clock::now();
    auto state = upsica::protocol::BuildReceiverVbfState(
        batch, deserializeOprf(oprf_payload), options.config);

    // The server degree follows the public sizes/configuration. A conservative
    // public upper bound avoids leaking actual sender bin occupancy.
    uint32_t maximum_power = upsica::protocol::PublicMaximumSubBinDegree(
        options.sender_size, options.config);
    auto query = upsica::protocol::EncryptReceiverVbfQuery(
        state, maximum_power, receiver_fhe,
        seal::PlainModulus::Batching(options.config.poly_modulus_degree,
                                     options.config.plain_modulus_bits).value());
    auto query_compute_end = Clock::now();
    upload += sendFrame(fd, MessageType::FheQuery, serializeQuery(query));
    uint64_t response_wire = 0;
    auto [response_type, response_payload] = receiveFrame(fd, response_wire);
    download += response_wire;
    if (response_type != MessageType::FheResponse) throw std::runtime_error("expected FHE response");
    auto decrypt_start = Clock::now();
    auto response = deserializeResponse(response_payload);
    uint64_t plain_modulus = seal::PlainModulus::Batching(
        options.config.poly_modulus_degree, options.config.plain_modulus_bits).value();
    uint64_t cardinality = upsica::protocol::DecryptIntersectionCardinality(
        state, response, receiver_fhe, plain_modulus);
    auto decrypt_end = Clock::now();
    auto online_wall_end = decrypt_end;
    close(fd);
    const uint64_t expected_cardinality =
        std::min(options.intersection, options.receiver_size);
    if (cardinality != expected_cardinality)
        throw std::runtime_error("cardinality verification failed: expected " +
                                 std::to_string(expected_cardinality) + ", got " +
                                 std::to_string(cardinality));

    const double client_compute = milliseconds(oprf_compute_start, oprf_compute_end) +
        milliseconds(query_compute_start, query_compute_end) +
        milliseconds(decrypt_start, decrypt_end);
    const uint64_t setup_key_bytes = 2 * sizeof(uint64_t) +
        query.evaluation_keys.public_key.size() + query.evaluation_keys.relin_keys.size();
    writeMetrics(options.results, {
        {"role", "client"}, {"receiver_set", std::to_string(options.receiver_size)},
        {"element_bits", std::to_string(options.element_bits)},
        {"intersection_cardinality", std::to_string(cardinality)},
        {"union_cardinality", std::to_string(options.sender_size + options.receiver_size - cardinality)},
        {"time_setup", std::to_string(milliseconds(setup_start, setup_end))},
        {"time_online_client_comp", std::to_string(client_compute)},
        {"time_online_client_oprf_blind", std::to_string(milliseconds(oprf_compute_start, oprf_compute_end))},
        {"time_online_client_query_comp", std::to_string(milliseconds(query_compute_start, query_compute_end))},
        {"time_online_client_decrypt", std::to_string(milliseconds(decrypt_start, decrypt_end))},
        {"time_online_wall", std::to_string(milliseconds(online_wall_start, online_wall_end))},
        {"comm_setup", std::to_string(setup_key_bytes)},
        {"comm_offline", "0"},
        {"comm_online", std::to_string(upload + download - setup_key_bytes)},
        {"comm_total", std::to_string(upload + download)},
        {"comm_online_upload", std::to_string(upload - setup_key_bytes)},
        {"comm_online_download", std::to_string(download)},
        {"oprf_requests", "1"}, {"fhe_queries", "1"}
    });
    std::cout << "intersection_cardinality=" << cardinality << '\n';
}

}  // namespace

int main(int argc, char** argv) {
    try {
        auto options = parseOptions(argc, argv);
        if (options.role == "server") runServer(options);
        else runClient(options);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "UPSICA error: " << error.what() << '\n';
        return 1;
    }
}
#include <algorithm>
