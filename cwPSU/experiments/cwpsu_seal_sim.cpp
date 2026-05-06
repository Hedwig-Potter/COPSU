#include <seal/seal.h>
#include <bits/stdc++.h>
using namespace std;
using namespace seal;

// 简化版 cwPSU 同态实验：
// - 使用 SEAL 中的 BFV 批量编码，将服务器指示向量加密；
// - 用明文随机数模拟服务器的掩码 r，并在 client 侧执行随机置换；
// - 利用 shares 还原掩码后的指示向量，进而筛选客户端元素；
// - 仅保留协议的数据流，忽略实际方案中的 OSN、OT 等密码原语。

int main(){
    cout << "cwPSU SEAL simulation start" << endl;

    size_t n = 16; // 批处理槽位数，与 BatchEncoder 的可用槽位前半部分对应

    // 服务器与客户端集合，直接用索引模拟元素
    vector<size_t> server_items = {1,3,5,10};
    vector<size_t> client_items = {2,3,7,10,12};

    // 配置 BFV 参数：多项式模数、系数模数与适合批量编码的明文模数
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    // 初始化 SEAL 上下文与常用算子
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);
    SecretKey sk = keygen.secret_key();
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    BatchEncoder batch(context);
    Evaluator evaluator(context);

    size_t slot_count = batch.slot_count();
    vector<uint64_t> ind_vec(slot_count, 0);
    for(auto x: server_items) if (x < slot_count) ind_vec[x] = 1;

    // 服务器采样随机掩码 r ∈ {0,1}^n
    vector<uint64_t> r_vec(slot_count, 0);
    mt19937_64 rng(123456);
    for(size_t i=0;i<slot_count;i++) r_vec[i] = rng() & 1;

    // 服务器计算 m = ind + r (mod p)
    vector<uint64_t> m_vec(slot_count);
    uint64_t p = parms.plain_modulus().value();
    for(size_t i=0;i<slot_count;i++) m_vec[i] = (ind_vec[i] + r_vec[i]) % p;

    // 对掩码后的向量加密
    Plaintext m_pt;
    batch.encode(m_vec, m_pt);
    Ciphertext m_ct;
    encryptor.encrypt(m_pt, m_ct);

    // 客户端选择随机置换 π，模拟 cwPSU 中的伪随机置换
    vector<size_t> pi(n);
    iota(pi.begin(), pi.end(), 0);
    shuffle(pi.begin(), pi.end(), rng);

    // 模拟 OSN：生成置换后的 r，并拆分成 server/client 两份 share
    vector<uint64_t> permuted_r(n);
    for(size_t i=0;i<n;i++) permuted_r[i] = r_vec[pi[i]];
    vector<uint64_t> s_s(n), s_c(n);
    for(size_t i=0;i<n;i++){
        s_s[i] = rng() & 1;
        s_c[i] = permuted_r[i] ^ s_s[i];
    }

    // 服务器将 s_s 打包加密发给客户端；此处用明文写回对应槽位后整体加密
    vector<uint64_t> s_s_slots(slot_count, 0);
    for(size_t i=0;i<n;i++) s_s_slots[pi[i]] = s_s[i]; // place server share in permuted positions
    Plaintext s_s_pt; batch.encode(s_s_slots, s_s_pt);
    Ciphertext s_s_ct; encryptor.encrypt(s_s_pt, s_s_ct);

    // 客户端需要对密文应用置换。为了演示方便，这里解密后置换再重新加密（真实实现应使用密文级别的旋转）
    Plaintext m_dec; decryptor.decrypt(m_ct, m_dec);
    vector<uint64_t> m_dec_vec; batch.decode(m_dec, m_dec_vec);
    vector<uint64_t> m_permuted(n);
    for(size_t i=0;i<n;i++) m_permuted[i] = m_dec_vec[pi[i]];

    // 按照协议合并 shares，抵消随机掩码
    vector<uint64_t> m_pks(n);
    for(size_t i=0;i<n;i++){
        uint64_t tmp = (m_permuted[i] + p - s_c[i] + p - s_s[i]) % p;
        m_pks[i] = tmp;
    }

    // 将 m_pks 写回槽位，方便与客户端元素逐槽相乘
    vector<uint64_t> m_pks_slots(slot_count, 0);
    for(size_t i=0;i<n;i++){
        // client keeps m_pks in index i (aligned with client items)
        m_pks_slots[i] = m_pks[i];
    }
    Plaintext m_pks_pt; batch.encode(m_pks_slots, m_pks_pt);

    // 客户端将自身元素嵌入槽位，数值增加偏移量 100 以演示载荷传输
    vector<uint64_t> client_elem_slots(slot_count, 0);
    for(size_t idx: client_items) if (idx < slot_count) client_elem_slots[idx] = idx + 100; // arbitrary payload
    Plaintext client_elem_pt; batch.encode(client_elem_slots, client_elem_pt);

    // 加密客户端元素，并与 m_pks_pt 做逐槽乘法（真实协议中为密文-明文乘）
    Ciphertext client_elem_ct; encryptor.encrypt(client_elem_pt, client_elem_ct);

    // 与选择向量相乘，筛掉非交集位置
    evaluator.multiply_plain_inplace(client_elem_ct, m_pks_pt);

    // 服务器解密后即可恢复被选中的客户端元素
    Plaintext res_pt; decryptor.decrypt(client_elem_ct, res_pt);
    vector<uint64_t> res_vec; batch.decode(res_pt, res_vec);

    cout << "Selected elements received by server: ";
    for(size_t i=0;i<n;i++) if (res_vec[i]) cout << res_vec[i] - 100 << " ";
    cout << '\n';

    cout << "cwPSU SEAL simulation done" << endl;
    return 0;
}
