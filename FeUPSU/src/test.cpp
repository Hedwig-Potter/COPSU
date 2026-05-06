#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main() {
    // 1. 配置 BFV 上下文，使用 4096 阶多项式和 20 位明文模数
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);

    // 2. 生成密钥对
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // 3. 创建编码器、加解密器、运算器
    BatchEncoder batch_encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);

    size_t slot_count = batch_encoder.slot_count();
    vector<uint64_t> a_bits(slot_count, 0ULL);
    vector<uint64_t> b_bits(slot_count, 0ULL);

    vector<int> a_vec = {0,1,1,1,0,0,0,1};
    vector<int> b_vec = {1,0,1,1,0,1,1,0};

    for (size_t i = 0; i < a_vec.size(); ++i) {
        a_bits[i] = static_cast<uint64_t>(a_vec[i]);
        b_bits[i] = static_cast<uint64_t>(b_vec[i]);
    }

    Plaintext plain_a;
    batch_encoder.encode(a_bits, plain_a);
    Plaintext plain_b;
    batch_encoder.encode(b_bits, plain_b);

    Ciphertext enc_a;
    encryptor.encrypt(plain_a, enc_a);

    Ciphertext enc_a_plus_b;
    evaluator.add_plain(enc_a, plain_b, enc_a_plus_b);

    Ciphertext enc_a_times_b;
    evaluator.multiply_plain(enc_a, plain_b, enc_a_times_b);

    Plaintext dbg_ab;
    decryptor.decrypt(enc_a_times_b, dbg_ab);
    vector<uint64_t> ab_slots;
    batch_encoder.decode(dbg_ab, ab_slots);

    Plaintext two_plain;
    batch_encoder.encode(vector<uint64_t>(slot_count, 2ULL), two_plain);

    evaluator.multiply_plain_inplace(enc_a_times_b, two_plain);

    evaluator.mod_switch_to_inplace(enc_a_plus_b, enc_a_times_b.parms_id());

    Plaintext dbg_plus;
    decryptor.decrypt(enc_a_plus_b, dbg_plus);
    vector<uint64_t> plus_slots;
    batch_encoder.decode(dbg_plus, plus_slots);

    Plaintext dbg_twoab;
    decryptor.decrypt(enc_a_times_b, dbg_twoab);
    vector<uint64_t> twoab_slots;
    batch_encoder.decode(dbg_twoab, twoab_slots);

    Ciphertext enc_ans;
    evaluator.sub(enc_a_plus_b, enc_a_times_b, enc_ans);

    Plaintext plain_ans;
    decryptor.decrypt(enc_ans, plain_ans);
    uint64_t plain_mod = parms.plain_modulus().value();
    cout << "plain_mod: " << plain_mod << endl;

    vector<uint64_t> result;
    batch_encoder.decode(plain_ans, result);

    cout << "raw slots: ";
    for (size_t i = 0; i < a_vec.size(); ++i) {
        cout << (result[i] % plain_mod) << ' ';
    }
    cout << endl;

    cout << "ab slots: ";
    for (size_t i = 0; i < a_vec.size(); ++i) {
        cout << static_cast<int64_t>(ab_slots[i] % plain_mod) << ' ';
    }
    cout << endl;

    cout << "a + b slots: ";
    for (size_t i = 0; i < a_vec.size(); ++i) {
        cout << static_cast<int64_t>(plus_slots[i] % plain_mod) << ' ';
    }
    cout << endl;

    cout << "2ab slots: ";
    for (size_t i = 0; i < a_vec.size(); ++i) {
        cout << static_cast<int64_t>(twoab_slots[i] % plain_mod) << ' ';
    }
    cout << endl;

    cout << "ans bits: ";
    for (size_t i = 0; i < a_vec.size(); ++i) {
        uint64_t val = result[i] % plain_mod;
        int64_t signed_val = (val <= plain_mod / 2)
            ? static_cast<int64_t>(val)
            : static_cast<int64_t>(val) - static_cast<int64_t>(plain_mod);
        uint64_t bit = static_cast<uint64_t>(signed_val & 1LL);
        cout << bit;
    }
    cout << endl;

    return 0;
}
