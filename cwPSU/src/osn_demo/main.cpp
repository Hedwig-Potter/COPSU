#ifndef ENABLE_BOOST
#define ENABLE_BOOST
#endif

#include <iostream>
#include <thread>
#include <vector>
#include <string>

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"

#include "OSNSender.h"
#include "OSNReceiver.h"

namespace oc = osuCrypto;

// DemoConfig 用于集中管理命令行可调参数
struct DemoConfig {
    std::string endpoint = "127.0.0.1:12121";
    std::size_t log_set_size = 4;    // 2^4 = 16 elements
    std::size_t num_threads = 1;
    int ot_type = 1;                 // 1 = IKNP OT, 2 = silent OT (requires cache)
};

// 构造演示用的输入集合，每个元素为唯一的 block
std::vector<oc::block> build_input(std::size_t size)
{
    std::vector<oc::block> inputs(size);
    for (std::size_t i = 0; i < size; ++i)
    {
    inputs[i] = oc::toBlock(0, static_cast<oc::u64>(i));
    }
    return inputs;
}

// run_sender 启动 OSN 发送端：生成通道、执行 permute+share 并记录置换
void run_sender(const DemoConfig& cfg, std::size_t set_size,
                std::vector<oc::block>& sender_shares, std::vector<int>& permutation)
{
    oc::IOService ios;
    oc::Session session(ios, cfg.endpoint, oc::EpMode::Server);
    std::vector<oc::Channel> channels(cfg.num_threads);
    for (auto& chl : channels)
    {
        chl = session.addChannel();
    }

    OSNSender sender;
    sender.init(set_size, cfg.ot_type, "osn_demo_cache");
    oc::Timer timer;
    sender.setTimer(timer);
    timer.setTimePoint("before run_osn");
    sender_shares = sender.run_osn(channels); // 得到发送端持有的随机份额 s_s
    timer.setTimePoint("after run_osn");
    permutation = sender.dest;

    std::cout << "[Sender]" << std::endl;
    std::cout << timer << std::endl;
    for (std::size_t i = 0; i < channels.size(); ++i)
    {
        auto sent = channels[i].getTotalDataSent();
        auto recv = channels[i].getTotalDataRecv();
        std::cout << "  Channel " << i
                  << " | sent=" << sent / 1024.0 / 1024.0 << " MB"
                  << " recv=" << recv / 1024.0 / 1024.0 << " MB" << std::endl;
    }

    for (auto& chl : channels)
    {
        chl.close();
    }
    session.stop();
}

// run_receiver 启动 OSN 接收端：带入输入集合，输出接收端的份额
void run_receiver(const DemoConfig& cfg, const std::vector<oc::block>& inputs,
                  std::vector<oc::block>& receiver_shares)
{
    oc::IOService ios;
    oc::Session session(ios, cfg.endpoint, oc::EpMode::Client);
    std::vector<oc::Channel> channels(cfg.num_threads);
    for (auto& chl : channels)
    {
        chl = session.addChannel();
    }

    OSNReceiver receiver;
    receiver.init(inputs.size(), cfg.ot_type);
    oc::Timer timer;
    receiver.setTimer(timer);
    timer.setTimePoint("before run_osn");
    receiver_shares = receiver.run_osn(inputs, channels); // 得到接收端份额 s_c
    timer.setTimePoint("after run_osn");

    std::cout << "[Receiver]" << std::endl;
    std::cout << timer << std::endl;
    for (std::size_t i = 0; i < channels.size(); ++i)
    {
        auto sent = channels[i].getTotalDataSent();
        auto recv = channels[i].getTotalDataRecv();
        std::cout << "  Channel " << i
                  << " | sent=" << sent / 1024.0 / 1024.0 << " MB"
                  << " recv=" << recv / 1024.0 / 1024.0 << " MB" << std::endl;
    }

    for (auto& chl : channels)
    {
        chl.close();
    }
    session.stop();
}

// 主函数组合同步启动 sender/receiver 并验证恢复效果
int main(int argc, char** argv)
{
    DemoConfig cfg;
    if (argc > 1)
    {
        cfg.log_set_size = static_cast<std::size_t>(std::stoul(argv[1]));
    }
    if (argc > 2)
    {
        cfg.num_threads = static_cast<std::size_t>(std::stoul(argv[2]));
    }
    if (argc > 3)
    {
        cfg.ot_type = std::stoi(argv[3]);
    }

    const std::size_t set_size = 1ULL << cfg.log_set_size;
    auto inputs = build_input(set_size); // 发送给接收端用的原始输入序列

    std::vector<oc::block> sender_shares;
    std::vector<oc::block> receiver_shares;
    std::vector<int> permutation;

    std::thread sender_thread(run_sender, std::ref(cfg), set_size,
                              std::ref(sender_shares), std::ref(permutation));
    std::thread receiver_thread(run_receiver, std::ref(cfg), std::cref(inputs),
                                std::ref(receiver_shares));

    sender_thread.join();
    receiver_thread.join();

    std::size_t correct = 0;
    for (std::size_t i = 0; i < set_size; ++i)
    {
        auto recovered = sender_shares[i] ^ receiver_shares[i]; // 份额异或重建
        if (recovered == inputs[permutation[i]]) // 应当等于被置换后的输入
        {
            ++correct;
        }
    }

    std::cout << "Recovered " << correct << "/" << set_size
              << " elements using OSN permute-share." << std::endl;

    return 0;
}
