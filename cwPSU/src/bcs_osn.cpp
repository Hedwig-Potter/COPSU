#include "bcs_osn.h"

#include "../osn/OSNSender.h"
#include "../osn/OSNReceiver.h"

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <ctime>
#include <cstring>
#include <exception>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace {

uint16_t next_local_port() {
    static std::atomic<uint16_t> port(15000);
    return port.fetch_add(1, std::memory_order_relaxed);
}

osuCrypto::block bit_to_block(uint64_t bit) {
    return osuCrypto::toBlock(0ULL, static_cast<osuCrypto::u64>(bit & 1ULL));
}

osuCrypto::block word_to_block(uint64_t value) {
    return osuCrypto::toBlock(0ULL, static_cast<osuCrypto::u64>(value));
}

uint64_t block_to_word(const osuCrypto::block& blk) {
    uint64_t value = 0;
    std::memcpy(&value, &blk, sizeof(uint64_t));
    return value;
}

uint64_t block_to_bit(const osuCrypto::block& blk) {
    uint64_t value = 0;
    std::memcpy(&value, &blk, sizeof(uint64_t));
    return value & 1ULL;
}

uint64_t thread_cpu_us() {
    timespec value{};
    if (::clock_gettime(CLOCK_THREAD_CPUTIME_ID, &value) != 0) return 0ULL;
    return static_cast<uint64_t>(value.tv_sec) * 1000000ULL
         + static_cast<uint64_t>(value.tv_nsec) / 1000ULL;
}

} // namespace

namespace bcs {

PartyShareOutput permute_share_sender(const std::vector<uint32_t>& permutation,
                                      const std::string& endpoint,
                                      int ot_type,
                                      const std::string& cache_base) {
    if (permutation.empty()) return {};
    std::vector<int> destinations(permutation.size());
    for (std::size_t i = 0; i < permutation.size(); ++i) {
        if (permutation[i] >= permutation.size()) {
            throw std::invalid_argument("permute_share_sender: invalid permutation");
        }
        destinations[i] = static_cast<int>(permutation[i]);
    }

    osuCrypto::IOService ios;
    osuCrypto::Session session(ios, endpoint, osuCrypto::EpMode::Server);
    std::vector<osuCrypto::Channel> channels(1);
    channels[0] = session.addChannel();
    OSNSender sender;
    sender.init(permutation.size(), ot_type, cache_base, &destinations);
    auto start = std::chrono::steady_clock::now();
    auto blocks = sender.run_osn(channels);
    auto end = std::chrono::steady_clock::now();

    PartyShareOutput output;
    output.compute_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
    output.comm_bytes = channels[0].getTotalDataSent();
    output.share.resize(blocks.size());
    std::transform(blocks.begin(), blocks.end(), output.share.begin(), block_to_word);
    channels[0].close();
    session.stop();
    return output;
}

PartyShareOutput permute_share_receiver(const std::vector<uint64_t>& values,
                                        const std::string& endpoint,
                                        int ot_type) {
    if (values.empty()) return {};
    osuCrypto::IOService ios;
    osuCrypto::Session session(ios, endpoint, osuCrypto::EpMode::Client);
    std::vector<osuCrypto::Channel> channels(1);
    channels[0] = session.addChannel();
    OSNReceiver receiver;
    receiver.init(values.size(), ot_type);
    std::vector<osuCrypto::block> inputs(values.size());
    std::transform(values.begin(), values.end(), inputs.begin(), word_to_block);
    auto start = std::chrono::steady_clock::now();
    auto blocks = receiver.run_osn(inputs, channels);
    auto end = std::chrono::steady_clock::now();

    PartyShareOutput output;
    output.compute_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
    output.comm_bytes = channels[0].getTotalDataSent();
    output.share.resize(blocks.size());
    std::transform(blocks.begin(), blocks.end(), output.share.begin(), block_to_word);
    channels[0].close();
    session.stop();
    return output;
}

PartyShareOutput permute_share_sender_arithmetic(
    const std::vector<uint32_t>& permutation, const std::string& endpoint,
    uint64_t modulus, int ot_type, const std::string& cache_base) {
    if (permutation.empty()) return {};
    if (modulus < 2) throw std::invalid_argument("arithmetic share modulus must be at least 2");
    const uint64_t cpu_start_us = thread_cpu_us();
    std::vector<int> destinations(permutation.size());
    for (std::size_t i = 0; i < permutation.size(); ++i) {
        if (permutation[i] >= permutation.size()) {
            throw std::invalid_argument("permute_share_sender_arithmetic: invalid permutation");
        }
        destinations[i] = static_cast<int>(permutation[i]);
    }
    osuCrypto::IOService ios;
    osuCrypto::Session session(ios, endpoint, osuCrypto::EpMode::Server);
    auto channel = session.addChannel();
    std::vector<osuCrypto::Channel> channels;
    channels.push_back(std::move(channel));
    OSNSender sender;
    sender.init(permutation.size(), ot_type, cache_base, &destinations);
    auto blocks = sender.run_osn_arithmetic(channels, modulus);
    PartyShareOutput output;
    output.comm_bytes = channels[0].getTotalDataSent();
    output.share.resize(blocks.size());
    std::transform(blocks.begin(), blocks.end(), output.share.begin(),
                   [modulus](const osuCrypto::block& block) { return block_to_word(block) % modulus; });
    const uint64_t cpu_end_us = thread_cpu_us();
    output.compute_us = cpu_end_us >= cpu_start_us ? cpu_end_us - cpu_start_us : 0ULL;
    output.compute_ms = (output.compute_us + 999ULL) / 1000ULL;
    channels[0].close();
    session.stop();
    return output;
}

PartyShareOutput permute_share_receiver_arithmetic(
    const std::vector<uint64_t>& values, const std::string& endpoint,
    uint64_t modulus, int ot_type) {
    if (values.empty()) return {};
    if (modulus < 2) throw std::invalid_argument("arithmetic share modulus must be at least 2");
    const uint64_t cpu_start_us = thread_cpu_us();
    osuCrypto::IOService ios;
    osuCrypto::Session session(ios, endpoint, osuCrypto::EpMode::Client);
    auto channel = session.addChannel();
    std::vector<osuCrypto::Channel> channels;
    channels.push_back(std::move(channel));
    OSNReceiver receiver;
    receiver.init(values.size(), ot_type);
    std::vector<osuCrypto::block> inputs(values.size());
    std::transform(values.begin(), values.end(), inputs.begin(),
                   [modulus](uint64_t value) { return word_to_block(value % modulus); });
    auto blocks = receiver.run_osn_arithmetic(inputs, channels, modulus);
    PartyShareOutput output;
    output.comm_bytes = channels[0].getTotalDataSent();
    output.share.resize(blocks.size());
    std::transform(blocks.begin(), blocks.end(), output.share.begin(),
                   [modulus](const osuCrypto::block& block) { return block_to_word(block) % modulus; });
    const uint64_t cpu_end_us = thread_cpu_us();
    output.compute_us = cpu_end_us >= cpu_start_us ? cpu_end_us - cpu_start_us : 0ULL;
    output.compute_ms = (output.compute_us + 999ULL) / 1000ULL;
    channels[0].close();
    session.stop();
    return output;
}

PermuteShareOutput permute_share_bits(const std::vector<uint64_t>& bits,
                                      const std::vector<uint32_t>& permutation,
                                      int ot_type,
                                      const std::string& cache_base) {
    if (bits.size() != permutation.size()) {
        throw std::invalid_argument("permute_share_bits: bits and permutation size mismatch");
    }

    const std::size_t set_size = bits.size();
    if (set_size == 0) {
        return PermuteShareOutput{};
    }

    std::string endpoint = "127.0.0.1:" + std::to_string(next_local_port());
    std::size_t num_threads = 1;

    std::vector<osuCrypto::block> sender_blocks;
    std::vector<osuCrypto::block> receiver_blocks;
    std::exception_ptr sender_exception;
    std::exception_ptr receiver_exception;
    uint64_t sender_bytes_sent = 0;
    uint64_t sender_compute_ms = 0;
    uint64_t receiver_compute_ms = 0;
    uint64_t sender_bytes_recv = 0;
    uint64_t receiver_bytes_sent = 0;
    uint64_t receiver_bytes_recv = 0;

    std::vector<int> dest_override(set_size);
    for (std::size_t i = 0; i < set_size; ++i) {
        dest_override[i] = static_cast<int>(permutation[i]);
    }

    auto total_start = std::chrono::steady_clock::now();
    std::thread sender_thread([&]() {
        try {
            osuCrypto::IOService ios;
            osuCrypto::Session session(ios, endpoint, osuCrypto::EpMode::Server);
            std::vector<osuCrypto::Channel> chls(num_threads);
            for (auto& chl : chls) {
                chl = session.addChannel();
            }

            OSNSender sender;
            sender.init(set_size, ot_type, cache_base, &dest_override);
            osuCrypto::Timer timer;
            sender.setTimer(timer);
            auto compute_start = std::chrono::steady_clock::now();
            sender_blocks = sender.run_osn(chls);
            auto compute_end = std::chrono::steady_clock::now();
            sender_compute_ms = std::chrono::duration_cast<std::chrono::milliseconds>(compute_end - compute_start).count();

            uint64_t local_sent = 0;
            uint64_t local_recv = 0;
            for (auto& chl : chls) {
                local_sent += chl.getTotalDataSent();
                local_recv += chl.getTotalDataRecv();
                chl.close();
            }
            sender_bytes_sent = local_sent;
            sender_bytes_recv = local_recv;
            session.stop();
        } catch (...) {
            sender_exception = std::current_exception();
        }
    });

    std::thread receiver_thread([&]() {
        try {
            osuCrypto::IOService ios;
            osuCrypto::Session session(ios, endpoint, osuCrypto::EpMode::Client);
            std::vector<osuCrypto::Channel> chls(num_threads);
            for (auto& chl : chls) {
                chl = session.addChannel();
            }

            OSNReceiver receiver;
            receiver.init(set_size, ot_type);

            std::vector<osuCrypto::block> input_blocks(set_size);
            for (std::size_t i = 0; i < set_size; ++i) {
                input_blocks[i] = bit_to_block(bits[i]);
            }

            auto compute_start = std::chrono::steady_clock::now();
            receiver_blocks = receiver.run_osn(input_blocks, chls);
            auto compute_end = std::chrono::steady_clock::now();
            receiver_compute_ms = std::chrono::duration_cast<std::chrono::milliseconds>(compute_end - compute_start).count();

            uint64_t local_sent = 0;
            uint64_t local_recv = 0;
            for (auto& chl : chls) {
                local_sent += chl.getTotalDataSent();
                local_recv += chl.getTotalDataRecv();
                chl.close();
            }
            receiver_bytes_sent = local_sent;
            receiver_bytes_recv = local_recv;
            session.stop();
        } catch (...) {
            receiver_exception = std::current_exception();
        }
    });

    sender_thread.join();
    receiver_thread.join();
    auto total_end = std::chrono::steady_clock::now();

    if (sender_exception) {
        std::rethrow_exception(sender_exception);
    }
    if (receiver_exception) {
        std::rethrow_exception(receiver_exception);
    }

    if (sender_blocks.size() != set_size || receiver_blocks.size() != set_size) {
        throw std::runtime_error("permute_share_bits: OSN output size mismatch");
    }

    PermuteShareOutput output;
    output.server_share.resize(set_size);
    output.client_share.resize(set_size);
    // The permute-share phase runs locally over osuCrypto channels, but we still
    // account for bytes sent in each direction so the caller can report
    // end-to-end communication.
    uint64_t total_sent = sender_bytes_sent + receiver_bytes_sent;
    uint64_t total_recv = sender_bytes_recv + receiver_bytes_recv;
    output.comm_bytes = total_sent;
    if (total_sent != total_recv) {
        output.comm_bytes = std::max(total_sent, total_recv);
    }
    // Sender thread owns the permutation (client role); receiver thread owns the
    // random bits (server role). Report their local compute costs separately.
    output.client_compute_ms = sender_compute_ms;
    output.server_compute_ms = receiver_compute_ms;
    uint64_t total_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(total_end - total_start).count());
    uint64_t max_compute_ms = std::max(sender_compute_ms, receiver_compute_ms);
    output.comm_ms = (total_ms > max_compute_ms) ? (total_ms - max_compute_ms) : 0;

    for (std::size_t i = 0; i < set_size; ++i) {
        output.client_share[i] = block_to_bit(sender_blocks[i]);
        output.server_share[i] = block_to_bit(receiver_blocks[i]);
    }

    return output;
}

} // namespace bcs
