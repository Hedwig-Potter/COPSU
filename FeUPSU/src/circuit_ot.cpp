#include "circuit_ot.h"

#include <array>
#include <chrono>
#include <cstring>
#include <stdexcept>

#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"

namespace circuit {
namespace {
uint64_t block_to_word(const osuCrypto::block& block) {
    uint64_t value = 0;
    std::memcpy(&value, &block, sizeof(value));
    return value;
}
}

PartyResult send_x_shares(const std::vector<uint64_t>& sx,
                          const std::vector<uint64_t>& sx_prime,
                          const std::vector<uint64_t>& shc,
                          const std::string& endpoint) {
    using namespace osuCrypto;
    if (sx.size() != sx_prime.size() || sx.size() != shc.size()) {
        throw std::invalid_argument("OT sender vector size mismatch");
    }
    if (sx.empty()) return {};
    IOService ios;
    Session session(ios, endpoint, SessionMode::Server);
    Channel channel = session.addChannel();
    PRNG prng(sysRandomSeed());
    IknpOtExtSender sender;
    auto start = std::chrono::steady_clock::now();
    sender.genBaseOts(prng, channel);
    std::vector<std::array<block, 2>> plaintexts(sx.size());
    for (std::size_t i = 0; i < sx.size(); ++i) {
        // When shc==shs, ct_ind=0 and x must be retained.  Otherwise the
        // receiver gets sx, which combines with the client's sx to dummy zero.
        // cryptoTools::toBlock(high, low); block_to_word reads the low lane.
        const block keep = toBlock(0ULL, sx_prime[i]);
        const block dummy = toBlock(0ULL, sx[i]);
        if ((shc[i] & 1ULL) == 0) {
            plaintexts[i] = {keep, dummy};
        } else {
            plaintexts[i] = {dummy, keep};
        }
    }
    // libOTe's IKNP interface below produces random OT keys.  Turn it into
    // chosen-message OT by one-time-padding each application message.
    std::vector<std::array<block, 2>> pads(sx.size());
    sender.send(pads, prng, channel);
    std::vector<std::array<block, 2>> masked(sx.size());
    for (std::size_t i = 0; i < sx.size(); ++i) {
        masked[i][0] = pads[i][0] ^ plaintexts[i][0];
        masked[i][1] = pads[i][1] ^ plaintexts[i][1];
    }
    channel.send(masked.data(), masked.size());
    auto end = std::chrono::steady_clock::now();
    PartyResult result;
    result.comm_bytes = channel.getTotalDataSent();
    result.compute_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
    channel.close();
    session.stop();
    return result;
}

PartyResult receive_x_shares(const std::vector<uint64_t>& shs,
                             const std::string& endpoint) {
    using namespace osuCrypto;
    if (shs.empty()) return {};
    IOService ios;
    Session session(ios, endpoint, SessionMode::Client);
    Channel channel = session.addChannel();
    PRNG prng(sysRandomSeed());
    IknpOtExtReceiver receiver;
    auto start = std::chrono::steady_clock::now();
    receiver.genBaseOts(prng, channel);
    BitVector choices(shs.size());
    for (std::size_t i = 0; i < shs.size(); ++i) {
        choices[i] = static_cast<u8>(shs[i] & 1ULL);
    }
    std::vector<block> received(shs.size());
    receiver.receive(choices, received, prng, channel);
    std::vector<std::array<block, 2>> masked(shs.size());
    channel.recv(masked.data(), masked.size());
    auto end = std::chrono::steady_clock::now();
    PartyResult result;
    result.values.resize(received.size());
    for (std::size_t i = 0; i < received.size(); ++i) {
        result.values[i] = block_to_word(received[i] ^ masked[i][choices[i] ? 1 : 0]);
    }
    result.comm_bytes = channel.getTotalDataSent();
    result.compute_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
    channel.close();
    session.stop();
    return result;
}

} // namespace circuit
