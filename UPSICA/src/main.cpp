// TCP-based sender/receiver runner with phase metrics and CSV export.
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
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "upsica/online_phase.h"
#include "upsica/preparation_phase.h"

namespace {

using Clock = std::chrono::steady_clock;

enum class MsgType : uint32_t {
    OfflineRequest = 1,
    OfflineResponse = 2,
    OnlineRequest = 3,
    OnlineResponse = 4,
    Shutdown = 5
};

struct PhaseMetrics {
    uint64_t upload_bytes = 0;
    uint64_t download_bytes = 0;
    double comm_ms = 0.0;
    double sender_compute_ms = 0.0;
    double receiver_compute_ms = 0.0;
};

struct SenderServerMetrics {
    double offline_compute_ms = 0.0;
    double online_compute_ms = 0.0;
    double offline_comm_ms = 0.0;
    double online_comm_ms = 0.0;
    uint64_t offline_upload_bytes = 0;
    uint64_t offline_download_bytes = 0;
    uint64_t online_upload_bytes = 0;
    uint64_t online_download_bytes = 0;
};

struct SenderRuntimeState {
    std::vector<uint64_t> sender_set;
    upsica::protocol::ProtocolConfig config;
    upsica::protocol::PreparationOutput prep;
    bool prep_ready = false;
    SenderServerMetrics metrics;
    std::mutex metrics_mu;
};

struct ByteWriter {
    std::vector<uint8_t> buf;

    template <typename T>
    void writePod(const T& v) {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&v);
        buf.insert(buf.end(), p, p + sizeof(T));
    }

    void writeString(const std::string& s) {
        uint64_t n = static_cast<uint64_t>(s.size());
        writePod(n);
        buf.insert(buf.end(), s.begin(), s.end());
    }

    template <typename T>
    void writeVector(const std::vector<T>& vec) {
        uint64_t n = static_cast<uint64_t>(vec.size());
        writePod(n);
        for (const auto& v : vec) {
            writePod(v);
        }
    }
};

struct ByteReader {
    const std::vector<uint8_t>& buf;
    size_t pos = 0;

    template <typename T>
    T readPod() {
        if (pos + sizeof(T) > buf.size()) {
            throw std::runtime_error("buffer underflow");
        }
        T v{};
        std::memcpy(&v, buf.data() + pos, sizeof(T));
        pos += sizeof(T);
        return v;
    }

    std::string readString() {
        uint64_t n = readPod<uint64_t>();
        if (pos + n > buf.size()) {
            throw std::runtime_error("buffer underflow string");
        }
        std::string s(reinterpret_cast<const char*>(buf.data() + pos), static_cast<size_t>(n));
        pos += static_cast<size_t>(n);
        return s;
    }

    template <typename T>
    std::vector<T> readVector() {
        uint64_t n = readPod<uint64_t>();
        std::vector<T> vec;
        vec.reserve(static_cast<size_t>(n));
        for (uint64_t i = 0; i < n; ++i) {
            vec.push_back(readPod<T>());
        }
        return vec;
    }
};

bool sendAll(int fd, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) {
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool recvAll(int fd, uint8_t* data, size_t len) {
    size_t recvd = 0;
    while (recvd < len) {
        ssize_t n = recv(fd, data + recvd, len - recvd, 0);
        if (n <= 0) {
            return false;
        }
        recvd += static_cast<size_t>(n);
    }
    return true;
}

bool sendFramedMessage(int fd, MsgType type, const std::vector<uint8_t>& payload, uint64_t& bytes_out) {
    uint32_t t = static_cast<uint32_t>(type);
    uint64_t len = static_cast<uint64_t>(sizeof(t) + payload.size());
    bytes_out += sizeof(len) + len;
    if (!sendAll(fd, reinterpret_cast<const uint8_t*>(&len), sizeof(len))) return false;
    if (!sendAll(fd, reinterpret_cast<const uint8_t*>(&t), sizeof(t))) return false;
    if (!payload.empty()) {
        if (!sendAll(fd, payload.data(), payload.size())) return false;
    }
    return true;
}

bool recvFramedMessage(int fd, MsgType& type, std::vector<uint8_t>& payload, uint64_t& bytes_in) {
    uint64_t len = 0;
    if (!recvAll(fd, reinterpret_cast<uint8_t*>(&len), sizeof(len))) return false;
    if (len < sizeof(uint32_t)) return false;
    std::vector<uint8_t> frame(len);
    if (!recvAll(fd, frame.data(), frame.size())) return false;
    bytes_in += sizeof(len) + len;
    ByteReader r{frame};
    uint32_t t = r.readPod<uint32_t>();
    type = static_cast<MsgType>(t);
    payload.assign(frame.begin() + static_cast<long>(r.pos), frame.end());
    return true;
}

void serializePackedCoeffs(ByteWriter& w, const upsica::protocol::PackedPolynomialCoefficients& p) {
    w.writePod<uint32_t>(p.max_degree);
    w.writePod<uint64_t>(static_cast<uint64_t>(p.coeffs_by_degree.size()));
    for (const auto& pt : p.coeffs_by_degree) {
        w.writeVector<uint64_t>(pt.slots);
    }
}

upsica::protocol::PackedPolynomialCoefficients deserializePackedCoeffs(ByteReader& r) {
    upsica::protocol::PackedPolynomialCoefficients p;
    p.max_degree = r.readPod<uint32_t>();
    uint64_t n = r.readPod<uint64_t>();
    p.coeffs_by_degree.reserve(static_cast<size_t>(n));
    for (uint64_t i = 0; i < n; ++i) {
        upsica::crypto::Plaintext pt;
        pt.slots = r.readVector<uint64_t>();
        p.coeffs_by_degree.push_back(std::move(pt));
    }
    return p;
}

std::vector<uint8_t> serializePreparationOutput(const upsica::protocol::PreparationOutput& p) {
    ByteWriter w;
    w.writePod<uint32_t>(p.config.bin_count);
    w.writePod<uint32_t>(p.config.fhe_poly_modulus_degree);
    w.writePod<uint32_t>(p.config.fhe_plain_modulus_bits);
    w.writePod<uint32_t>(p.config.alpha_sub_bins);
    w.writePod<uint32_t>(p.config.cuckoo_hash_num);
    w.writePod<uint32_t>(p.config.cuckoo_max_kicks);
    w.writePod<uint64_t>(p.config.dummy_seed);
    w.writePod<uint8_t>(p.config.enable_polynomial_links ? 1 : 0);

    w.writePod<uint32_t>(p.slot_count);
    w.writePod<uint64_t>(p.plain_modulus);
    w.writeString(p.oprf_secret_key_hex);
    w.writeVector<uint64_t>(p.sender_oprf_values);
    w.writePod<uint32_t>(p.alpha_sub_bins);

    w.writePod<uint64_t>(static_cast<uint64_t>(p.bin_polynomials.size()));
    for (const auto& bp : p.bin_polynomials) {
        w.writePod<uint32_t>(bp.sender_points);
        w.writeVector<uint32_t>(bp.sub_bin_points);
    }

    auto writePackedVec = [&](const std::vector<upsica::protocol::PackedPolynomialCoefficients>& vec) {
        w.writePod<uint64_t>(static_cast<uint64_t>(vec.size()));
        for (const auto& packed : vec) {
            serializePackedCoeffs(w, packed);
        }
    };
    writePackedVec(p.packed_root_coeffs_by_subbin);
    writePackedVec(p.packed_link2_coeffs_by_subbin);
    writePackedVec(p.packed_link3_coeffs_by_subbin);
    return w.buf;
}

upsica::protocol::PreparationOutput deserializePreparationOutput(const std::vector<uint8_t>& data) {
    ByteReader r{data};
    upsica::protocol::PreparationOutput p;
    p.config.bin_count = r.readPod<uint32_t>();
    p.config.fhe_poly_modulus_degree = r.readPod<uint32_t>();
    p.config.fhe_plain_modulus_bits = r.readPod<uint32_t>();
    p.config.alpha_sub_bins = r.readPod<uint32_t>();
    p.config.cuckoo_hash_num = r.readPod<uint32_t>();
    p.config.cuckoo_max_kicks = r.readPod<uint32_t>();
    p.config.dummy_seed = r.readPod<uint64_t>();
    p.config.enable_polynomial_links = (r.readPod<uint8_t>() != 0);

    p.slot_count = r.readPod<uint32_t>();
    p.plain_modulus = r.readPod<uint64_t>();
    p.oprf_secret_key_hex = r.readString();
    p.sender_oprf_values = r.readVector<uint64_t>();
    p.alpha_sub_bins = r.readPod<uint32_t>();

    uint64_t bins = r.readPod<uint64_t>();
    p.bin_polynomials.resize(static_cast<size_t>(bins));
    for (uint64_t i = 0; i < bins; ++i) {
        p.bin_polynomials[i].sender_points = r.readPod<uint32_t>();
        p.bin_polynomials[i].sub_bin_points = r.readVector<uint32_t>();
    }

    auto readPackedVec = [&](std::vector<upsica::protocol::PackedPolynomialCoefficients>& vec) {
        uint64_t n = r.readPod<uint64_t>();
        vec.resize(static_cast<size_t>(n));
        for (uint64_t i = 0; i < n; ++i) {
            vec[i] = deserializePackedCoeffs(r);
        }
    };
    readPackedVec(p.packed_root_coeffs_by_subbin);
    readPackedVec(p.packed_link2_coeffs_by_subbin);
    readPackedVec(p.packed_link3_coeffs_by_subbin);
    return p;
}

std::vector<uint8_t> serializeOnlineOutput(const upsica::protocol::OnlineOutput& o) {
    ByteWriter w;
    w.writePod<uint64_t>(o.intersection_cardinality);
    w.writeVector<uint64_t>(o.receiver_oprf_values);
    w.writeVector<uint64_t>(o.matched_oprf_values);
    w.writePod<uint8_t>(o.used_fhe_online ? 1 : 0);
    w.writePod<uint8_t>(o.used_polynomial_links ? 1 : 0);
    w.writePod<uint8_t>(o.used_cuckoo_hashing ? 1 : 0);
    w.writePod<uint8_t>(o.used_sender_simple_hashing ? 1 : 0);
    w.writePod<uint64_t>(o.bin_count);
    w.writePod<uint64_t>(o.alpha_sub_bins);
    w.writePod<uint64_t>(o.cuckoo_items_placed);
    w.writePod<uint64_t>(o.cuckoo_items_dropped);
    w.writePod<uint64_t>(o.encrypted_query_slices);
    w.writePod<uint64_t>(o.sender_evaluated_slices);
    w.writePod<uint64_t>(o.returned_ciphertexts);
    return w.buf;
}

upsica::protocol::OnlineOutput deserializeOnlineOutput(const std::vector<uint8_t>& data) {
    ByteReader r{data};
    upsica::protocol::OnlineOutput o;
    o.intersection_cardinality = r.readPod<uint64_t>();
    o.receiver_oprf_values = r.readVector<uint64_t>();
    o.matched_oprf_values = r.readVector<uint64_t>();
    o.used_fhe_online = (r.readPod<uint8_t>() != 0);
    o.used_polynomial_links = (r.readPod<uint8_t>() != 0);
    o.used_cuckoo_hashing = (r.readPod<uint8_t>() != 0);
    o.used_sender_simple_hashing = (r.readPod<uint8_t>() != 0);
    o.bin_count = r.readPod<uint64_t>();
    o.alpha_sub_bins = r.readPod<uint64_t>();
    o.cuckoo_items_placed = r.readPod<uint64_t>();
    o.cuckoo_items_dropped = r.readPod<uint64_t>();
    o.encrypted_query_slices = r.readPod<uint64_t>();
    o.sender_evaluated_slices = r.readPod<uint64_t>();
    o.returned_ciphertexts = r.readPod<uint64_t>();
    return o;
}

void senderServerLoop(uint16_t port, SenderRuntimeState* state) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        throw std::runtime_error("failed to create sender listen socket");
    }
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(listen_fd);
        throw std::runtime_error("failed to bind sender socket");
    }
    if (listen(listen_fd, 1) < 0) {
        close(listen_fd);
        throw std::runtime_error("failed to listen sender socket");
    }

    int conn_fd = accept(listen_fd, nullptr, nullptr);
    close(listen_fd);
    if (conn_fd < 0) {
        throw std::runtime_error("failed to accept receiver connection");
    }

    bool running = true;
    while (running) {
        MsgType type;
        std::vector<uint8_t> payload;
        uint64_t recv_bytes = 0;
        auto comm_recv_start = Clock::now();
        if (!recvFramedMessage(conn_fd, type, payload, recv_bytes)) {
            break;
        }
        auto comm_recv_end = Clock::now();
        double recv_ms = std::chrono::duration<double, std::milli>(comm_recv_end - comm_recv_start).count();

        if (type == MsgType::OfflineRequest) {
            auto t0 = Clock::now();
            state->prep = upsica::protocol::RunPreparation(state->sender_set, state->config);
            state->prep_ready = true;
            auto t1 = Clock::now();
            double compute_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

            ByteWriter w;
            w.writePod<double>(compute_ms);
            auto prep_bytes = serializePreparationOutput(state->prep);
            w.writePod<uint64_t>(static_cast<uint64_t>(prep_bytes.size()));
            w.buf.insert(w.buf.end(), prep_bytes.begin(), prep_bytes.end());

            uint64_t sent_bytes = 0;
            auto send_start = Clock::now();
            if (!sendFramedMessage(conn_fd, MsgType::OfflineResponse, w.buf, sent_bytes)) {
                break;
            }
            auto send_end = Clock::now();
            double send_ms = std::chrono::duration<double, std::milli>(send_end - send_start).count();

            std::lock_guard<std::mutex> lk(state->metrics_mu);
            state->metrics.offline_compute_ms = compute_ms;
            state->metrics.offline_comm_ms += recv_ms + send_ms;
            state->metrics.offline_upload_bytes += recv_bytes;
            state->metrics.offline_download_bytes += sent_bytes;
        } else if (type == MsgType::OnlineRequest) {
            if (!state->prep_ready) {
                throw std::runtime_error("online request before offline prep");
            }
            ByteReader r{payload};
            auto receiver_set = r.readVector<uint64_t>();

            auto t0 = Clock::now();
            auto out = upsica::protocol::RunOnline(receiver_set, state->prep);
            auto t1 = Clock::now();
            double compute_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

            ByteWriter w;
            w.writePod<double>(compute_ms);
            auto out_bytes = serializeOnlineOutput(out);
            w.writePod<uint64_t>(static_cast<uint64_t>(out_bytes.size()));
            w.buf.insert(w.buf.end(), out_bytes.begin(), out_bytes.end());

            uint64_t sent_bytes = 0;
            auto send_start = Clock::now();
            if (!sendFramedMessage(conn_fd, MsgType::OnlineResponse, w.buf, sent_bytes)) {
                break;
            }
            auto send_end = Clock::now();
            double send_ms = std::chrono::duration<double, std::milli>(send_end - send_start).count();

            std::lock_guard<std::mutex> lk(state->metrics_mu);
            state->metrics.online_compute_ms = compute_ms;
            state->metrics.online_comm_ms += recv_ms + send_ms;
            state->metrics.online_upload_bytes += recv_bytes;
            state->metrics.online_download_bytes += sent_bytes;
        } else if (type == MsgType::Shutdown) {
            running = false;
        } else {
            throw std::runtime_error("unknown message type");
        }
    }

    close(conn_fd);
}

void appendMetricsCsv(const std::string& csv_path,
                      uint32_t element_bits,
                      size_t sender_size,
                      size_t receiver_size,
                      const PhaseMetrics& offline,
                      const PhaseMetrics& online,
                      const upsica::protocol::OnlineOutput& out,
                      const SenderServerMetrics& sender_metrics) {
    namespace fs = std::filesystem;
    fs::path p(csv_path);
    if (!p.parent_path().empty()) {
        fs::create_directories(p.parent_path());
    }
    bool need_header = !fs::exists(p);
    std::ofstream ofs(csv_path, std::ios::app);
    if (!ofs) {
        throw std::runtime_error("failed to open csv file");
    }
    if (need_header) {
        ofs << "element_bits,sender_set_size,receiver_set_size,"
            << "offline_upload_bytes,offline_download_bytes,offline_total_bytes,"
            << "online_upload_bytes,online_download_bytes,online_total_bytes,"
            << "receiver_offline_comm_ms,receiver_offline_compute_ms,sender_offline_compute_ms,sender_offline_comm_ms,"
            << "receiver_online_comm_ms,receiver_online_compute_ms,sender_online_compute_ms,sender_online_comm_ms,"
            << "intersection_cardinality,bin_count,alpha_sub_bins,cuckoo_placed,cuckoo_dropped,"
            << "encrypted_query_slices,sender_evaluated_slices,returned_ciphertexts"
            << "\n";
    }
    ofs << element_bits << ","
        << sender_size << ","
        << receiver_size << ","
        << offline.upload_bytes << ","
        << offline.download_bytes << ","
        << (offline.upload_bytes + offline.download_bytes) << ","
        << online.upload_bytes << ","
        << online.download_bytes << ","
        << (online.upload_bytes + online.download_bytes) << ","
        << offline.comm_ms << ","
        << offline.receiver_compute_ms << ","
        << sender_metrics.offline_compute_ms << ","
        << sender_metrics.offline_comm_ms << ","
        << online.comm_ms << ","
        << online.receiver_compute_ms << ","
        << sender_metrics.online_compute_ms << ","
        << sender_metrics.online_comm_ms << ","
        << out.intersection_cardinality << ","
        << out.bin_count << ","
        << out.alpha_sub_bins << ","
        << out.cuckoo_items_placed << ","
        << out.cuckoo_items_dropped << ","
        << out.encrypted_query_slices << ","
        << out.sender_evaluated_slices << ","
        << out.returned_ciphertexts
        << "\n";
}

}  // namespace

int main(int argc, char** argv) {
    
    // 1. 设置默认参数（防止本地直接运行报错）
    uint64_t nx_size = 1 << 18;
    uint64_t ny_size = 1 << 10;
    uint32_t bit_length = 32;
    std::string net_env = "LAN";
    std::string csv_path = "benchmark_results.csv"; // 移除原来的绝对路径

    // 2. 接收 benchmark.sh 传来的参数
    if (argc >= 5) {
        nx_size = std::stoull(argv[1]);
        ny_size = std::stoull(argv[2]);
        bit_length = std::stoul(argv[3]);
        net_env = argv[4];
    }
    if (argc >= 6) {
        csv_path = argv[5];
    }

    // 自动创建输出文件夹（如果传进来的是 ./results/xxx.csv）
    std::filesystem::path p(csv_path);
    if (p.has_parent_path()) {
        std::filesystem::create_directories(p.parent_path());
    }

    const uint16_t port = 19090;

    // 3. 动态生成测试集合（替换原来的硬编码集合）
    std::vector<uint64_t> sender_set(nx_size);
    std::vector<uint64_t> receiver_set(ny_size);
    
    std::mt19937_64 rng(42); // 固定种子保证实验可复现
    uint64_t mask = (bit_length < 64) ? ((1ULL << bit_length) - 1) : ~0ULL;
    for (auto& val : sender_set) { val = rng() & mask; }
    for (auto& val : receiver_set) { val = rng() & mask; }

    upsica::protocol::ProtocolConfig config;
    
    // 注意：这里的 bin_count 需要能装下 nx_size。
    // 如果之前为了本地测试写死了 32，在大规模测试时必须调大，比如至少 nx_size / 某个因子
    // 如果你在代码里已经做过动态计算，可以直接设一个合理的常量，比如 8192 或更大
    config.bin_count = 8192; 
    config.fhe_poly_modulus_degree = 8192; // 随之放大以支持 SIMD capacity
    config.alpha_sub_bins = 4;
    config.enable_polynomial_links = true;

    SenderRuntimeState sender_state;
    sender_state.sender_set = sender_set;
    sender_state.config = config;

    std::thread sender_thread([&]() {
        senderServerLoop(port, &sender_state);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        throw std::runtime_error("receiver failed to create socket");
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        throw std::runtime_error("receiver failed to connect sender");
    }

    PhaseMetrics offline_metrics;
    PhaseMetrics online_metrics;

    // Offline phase over TCP.
    {
        uint64_t sent_bytes = 0;
        auto comm_start = Clock::now();
        if (!sendFramedMessage(fd, MsgType::OfflineRequest, {}, sent_bytes)) {
            throw std::runtime_error("failed to send offline request");
        }
        offline_metrics.upload_bytes += sent_bytes;

        MsgType resp_type;
        std::vector<uint8_t> resp_payload;
        uint64_t recv_bytes = 0;
        if (!recvFramedMessage(fd, resp_type, resp_payload, recv_bytes) || resp_type != MsgType::OfflineResponse) {
            throw std::runtime_error("failed to receive offline response");
        }
        auto comm_end = Clock::now();
        offline_metrics.download_bytes += recv_bytes;
        offline_metrics.comm_ms = std::chrono::duration<double, std::milli>(comm_end - comm_start).count();

        auto parse_start = Clock::now();
        ByteReader r{resp_payload};
        offline_metrics.sender_compute_ms = r.readPod<double>();
        uint64_t prep_len = r.readPod<uint64_t>();
        if (r.pos + prep_len > resp_payload.size()) {
            throw std::runtime_error("invalid prep payload length");
        }
        std::vector<uint8_t> prep_bytes(resp_payload.begin() + static_cast<long>(r.pos),
                                        resp_payload.begin() + static_cast<long>(r.pos + prep_len));
        auto prep_out = deserializePreparationOutput(prep_bytes);
        (void)prep_out;
        auto parse_end = Clock::now();
        offline_metrics.receiver_compute_ms =
            std::chrono::duration<double, std::milli>(parse_end - parse_start).count();
    }

    upsica::protocol::OnlineOutput online_out;

    // Online phase over TCP.
    {
        ByteWriter req;
        req.writeVector<uint64_t>(receiver_set);

        uint64_t sent_bytes = 0;
        auto comm_start = Clock::now();
        if (!sendFramedMessage(fd, MsgType::OnlineRequest, req.buf, sent_bytes)) {
            throw std::runtime_error("failed to send online request");
        }
        online_metrics.upload_bytes += sent_bytes;

        MsgType resp_type;
        std::vector<uint8_t> resp_payload;
        uint64_t recv_bytes = 0;
        if (!recvFramedMessage(fd, resp_type, resp_payload, recv_bytes) || resp_type != MsgType::OnlineResponse) {
            throw std::runtime_error("failed to receive online response");
        }
        auto comm_end = Clock::now();
        online_metrics.download_bytes += recv_bytes;
        online_metrics.comm_ms = std::chrono::duration<double, std::milli>(comm_end - comm_start).count();

        auto parse_start = Clock::now();
        ByteReader r{resp_payload};
        online_metrics.sender_compute_ms = r.readPod<double>();
        uint64_t out_len = r.readPod<uint64_t>();
        if (r.pos + out_len > resp_payload.size()) {
            throw std::runtime_error("invalid online payload length");
        }
        std::vector<uint8_t> out_bytes(resp_payload.begin() + static_cast<long>(r.pos),
                                       resp_payload.begin() + static_cast<long>(r.pos + out_len));
        online_out = deserializeOnlineOutput(out_bytes);
        auto parse_end = Clock::now();
        online_metrics.receiver_compute_ms =
            std::chrono::duration<double, std::milli>(parse_end - parse_start).count();
    }

    uint64_t shutdown_bytes = 0;
    sendFramedMessage(fd, MsgType::Shutdown, {}, shutdown_bytes);
    close(fd);
    sender_thread.join();

    SenderServerMetrics sender_metrics;
    {
        std::lock_guard<std::mutex> lk(sender_state.metrics_mu);
        sender_metrics = sender_state.metrics;
    }

    appendMetricsCsv(
        csv_path,
        bit_length, // <-- 传入动态位宽
        sender_set.size(),
        receiver_set.size(),
        offline_metrics,
        online_metrics,
        online_out,
        sender_metrics);

    std::cout << "Online intersection cardinality = " << online_out.intersection_cardinality << "\n";
    std::cout << "Offline bytes (up/down/total): "
              << offline_metrics.upload_bytes << "/" << offline_metrics.download_bytes << "/"
              << (offline_metrics.upload_bytes + offline_metrics.download_bytes) << "\n";
    std::cout << "Online bytes (up/down/total): "
              << online_metrics.upload_bytes << "/" << online_metrics.download_bytes << "/"
              << (online_metrics.upload_bytes + online_metrics.download_bytes) << "\n";
    std::cout << "CSV written to: " << csv_path << "\n";

    return 0;
}
