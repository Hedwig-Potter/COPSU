#include <seal/seal.h>
#include <bits/stdc++.h>
using namespace std;
using namespace seal;


int main(){
    cout << "cwPSU SEAL simulation start" << endl;

    size_t n = 16;

    vector<size_t> server_items = {1,3,5,10};
    vector<size_t> client_items = {2,3,7,10,12};

    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

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

    vector<uint64_t> r_vec(slot_count, 0);
    mt19937_64 rng(123456);
    for(size_t i=0;i<slot_count;i++) r_vec[i] = rng() & 1;

    vector<uint64_t> m_vec(slot_count);
    uint64_t p = parms.plain_modulus().value();
    for(size_t i=0;i<slot_count;i++) m_vec[i] = (ind_vec[i] + r_vec[i]) % p;

    Plaintext m_pt;
    batch.encode(m_vec, m_pt);
    Ciphertext m_ct;
    encryptor.encrypt(m_pt, m_ct);

    vector<size_t> pi(n);
    iota(pi.begin(), pi.end(), 0);
    shuffle(pi.begin(), pi.end(), rng);

    vector<uint64_t> permuted_r(n);
    for(size_t i=0;i<n;i++) permuted_r[i] = r_vec[pi[i]];
    vector<uint64_t> s_s(n), s_c(n);
    for(size_t i=0;i<n;i++){
        s_s[i] = rng() & 1;
        s_c[i] = permuted_r[i] ^ s_s[i];
    }

    vector<uint64_t> s_s_slots(slot_count, 0);
    for(size_t i=0;i<n;i++) s_s_slots[pi[i]] = s_s[i]; // place server share in permuted positions
    Plaintext s_s_pt; batch.encode(s_s_slots, s_s_pt);
    Ciphertext s_s_ct; encryptor.encrypt(s_s_pt, s_s_ct);

    Plaintext m_dec; decryptor.decrypt(m_ct, m_dec);
    vector<uint64_t> m_dec_vec; batch.decode(m_dec, m_dec_vec);
    vector<uint64_t> m_permuted(n);
    for(size_t i=0;i<n;i++) m_permuted[i] = m_dec_vec[pi[i]];

    vector<uint64_t> m_pks(n);
    for(size_t i=0;i<n;i++){
        uint64_t tmp = (m_permuted[i] + p - s_c[i] + p - s_s[i]) % p;
        m_pks[i] = tmp;
    }

    vector<uint64_t> m_pks_slots(slot_count, 0);
    for(size_t i=0;i<n;i++){
        // client keeps m_pks in index i (aligned with client items)
        m_pks_slots[i] = m_pks[i];
    }
    Plaintext m_pks_pt; batch.encode(m_pks_slots, m_pks_pt);

    vector<uint64_t> client_elem_slots(slot_count, 0);
    for(size_t idx: client_items) if (idx < slot_count) client_elem_slots[idx] = idx + 100; // arbitrary payload
    Plaintext client_elem_pt; batch.encode(client_elem_slots, client_elem_pt);

    Ciphertext client_elem_ct; encryptor.encrypt(client_elem_pt, client_elem_ct);

    evaluator.multiply_plain_inplace(client_elem_ct, m_pks_pt);

    Plaintext res_pt; decryptor.decrypt(client_elem_ct, res_pt);
    vector<uint64_t> res_vec; batch.decode(res_pt, res_vec);

    cout << "Selected elements received by server: ";
    for(size_t i=0;i<n;i++) if (res_vec[i]) cout << res_vec[i] - 100 << " ";
    cout << '\n';

    cout << "cwPSU SEAL simulation done" << endl;
    return 0;
}
