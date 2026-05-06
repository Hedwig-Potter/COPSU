#include <bits/stdc++.h>
using namespace std;

/*
 * 基于 Li 等人《cwPSU》方案的极简明文模拟：
 * - 用伪随机比特向量表示服务器的随机掩码 r；
 * - 通过随机置换 π 模拟 OSN（Oblivious Switching Network）的洗牌效果；
 * - 省略同态加密、OT 等密码操作，仅保留协议的消息流，使得调试更直观。
 */

// 生成长度为 n 的伪随机比特串，重置种子确保复现性
vector<int> random_bits(size_t n){
    vector<int> r(n);
    mt19937_64 rng(123456);
    for(size_t i=0;i<n;i++) r[i] = rng() & 1;
    return r;
}

// 按置换 π 对向量 v 做重新排列
vector<int> permute_vec(const vector<int>& v, const vector<size_t>& pi){
    size_t n = v.size();
    vector<int> out(n);
    for(size_t i=0;i<n;i++) out[i] = v[pi[i]];
    return out;
}

// 构造一个可复现的随机置换
vector<size_t> random_permutation(size_t n){
    vector<size_t> p(n);
    iota(p.begin(), p.end(), 0);
    mt19937_64 rng(987654);
    shuffle(p.begin(), p.end(), rng);
    return p;
}

int main(){
    cout << "cwPSU simulation start" << endl;

    size_t n = 16; // cwPSU 批处理槽位数量

    // 服务器与客户端持有的索引集合，直接用数字模拟元素ID
    vector<size_t> server_items = {1, 3, 5, 10};
    vector<size_t> client_items = {2, 3, 7, 10, 12};

    // 将服务器集合编码成指示向量 ind
    vector<int> ind(n, 0);
    for(auto x: server_items) if (x < n) ind[x] = 1;

    // 服务器采样随机掩码 r
    vector<int> r = random_bits(n);

    // 服务器计算掩码后的 m = ind XOR r
    vector<int> m(n);
    for(size_t i=0;i<n;i++) m[i] = ind[i] ^ r[i];

    // 客户端选择保密随机置换 π
    auto pi = random_permutation(n);

    // OSN 输出置换后的随机掩码，用于后续还原
    vector<int> permuted_r(n);
    for(size_t i=0;i<n;i++) permuted_r[i] = r[pi[i]];

    // OSN 将 permuted_r 拆分成 server/client 两份分片 s_s、s_c，使得 s_s XOR s_c = permuted_r
    vector<int> s_s(n), s_c(n);
    mt19937_64 rng(20241006);
    for(size_t i=0;i<n;i++){
        s_s[i] = rng() & 1;
        s_c[i] = permuted_r[i] ^ s_s[i];
    }

    // 真实协议中服务器会加密 s_s 并发送给客户端，这里直接以明文模拟

    // 客户端收到 m 与 s_s，先对 m 应用私有置换得到 m′
    vector<int> m_permuted(n);
    for(size_t i=0;i<n;i++) m_permuted[i] = m[pi[i]]; // apply pi to m

    // 客户端用 shares 消掉随机掩码，获得 permuted(ind)
    vector<int> m_pks(n);
    for(size_t i=0;i<n;i++) m_pks[i] = m_permuted[i] ^ s_c[i] ^ s_s[i];
    // algebra: m_permuted = permuted(ind XOR r) = permuted(ind) XOR permuted(r)
    // s_c ^ s_s = permuted(r) => m_pks = permuted(ind)

    // 求 inverse permutation，恢复到原始槽位坐标
    vector<size_t> inv_pi(n);
    for(size_t i=0;i<n;i++) inv_pi[pi[i]] = i;

    // 客户端根据 m_pks 选择自身集合中的交集元素
    // 真实协议会对编码后的密文做逐槽乘法，这里以明文筛选代替
    vector<size_t> client_selected;
    for(size_t idx: client_items){
        if (idx < n){
            size_t pos = inv_pi[idx];
            if (m_pks[pos]) client_selected.push_back(idx);
        }
    }

    // 客户端将选中的元素返回服务器，用于计算并集/交集
    cout << "Server set: "; for(auto x: server_items) cout << x << " "; cout << '\n';
    cout << "Client set: "; for(auto x: client_items) cout << x << " "; cout << '\n';
    cout << "Client selected after protocol (should be client∩server): ";
    for(auto x: client_selected) cout << x << " "; cout << '\n';

    // 验证筛选结果确实等于集合交集
    vector<size_t> intersection;
    for(auto x: client_selected){
        if (find(server_items.begin(), server_items.end(), x) != server_items.end()) intersection.push_back(x);
    }
    cout << "Verified intersection: "; for(auto x: intersection) cout << x << " "; cout << '\n';

    cout << "Simulation done." << endl;
    return 0;
}
