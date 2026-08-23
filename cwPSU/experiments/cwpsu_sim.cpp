#include <bits/stdc++.h>
using namespace std;

/*
 */

vector<int> random_bits(size_t n){
    vector<int> r(n);
    mt19937_64 rng(123456);
    for(size_t i=0;i<n;i++) r[i] = rng() & 1;
    return r;
}

vector<int> permute_vec(const vector<int>& v, const vector<size_t>& pi){
    size_t n = v.size();
    vector<int> out(n);
    for(size_t i=0;i<n;i++) out[i] = v[pi[i]];
    return out;
}

vector<size_t> random_permutation(size_t n){
    vector<size_t> p(n);
    iota(p.begin(), p.end(), 0);
    mt19937_64 rng(987654);
    shuffle(p.begin(), p.end(), rng);
    return p;
}

int main(){
    cout << "cwPSU simulation start" << endl;

    size_t n = 16;

    vector<size_t> server_items = {1, 3, 5, 10};
    vector<size_t> client_items = {2, 3, 7, 10, 12};

    vector<int> ind(n, 0);
    for(auto x: server_items) if (x < n) ind[x] = 1;

    vector<int> r = random_bits(n);

    vector<int> m(n);
    for(size_t i=0;i<n;i++) m[i] = ind[i] ^ r[i];

    auto pi = random_permutation(n);

    vector<int> permuted_r(n);
    for(size_t i=0;i<n;i++) permuted_r[i] = r[pi[i]];

    vector<int> s_s(n), s_c(n);
    mt19937_64 rng(20241006);
    for(size_t i=0;i<n;i++){
        s_s[i] = rng() & 1;
        s_c[i] = permuted_r[i] ^ s_s[i];
    }


    vector<int> m_permuted(n);
    for(size_t i=0;i<n;i++) m_permuted[i] = m[pi[i]]; // apply pi to m

    vector<int> m_pks(n);
    for(size_t i=0;i<n;i++) m_pks[i] = m_permuted[i] ^ s_c[i] ^ s_s[i];
    // algebra: m_permuted = permuted(ind XOR r) = permuted(ind) XOR permuted(r)
    // s_c ^ s_s = permuted(r) => m_pks = permuted(ind)

    vector<size_t> inv_pi(n);
    for(size_t i=0;i<n;i++) inv_pi[pi[i]] = i;

    vector<size_t> client_selected;
    for(size_t idx: client_items){
        if (idx < n){
            size_t pos = inv_pi[idx];
            if (m_pks[pos]) client_selected.push_back(idx);
        }
    }

    cout << "Server set: "; for(auto x: server_items) cout << x << " "; cout << '\n';
    cout << "Client set: "; for(auto x: client_items) cout << x << " "; cout << '\n';
    cout << "Client selected after protocol (should be client∩server): ";
    for(auto x: client_selected) cout << x << " "; cout << '\n';

    vector<size_t> intersection;
    for(auto x: client_selected){
        if (find(server_items.begin(), server_items.end(), x) != server_items.end()) intersection.push_back(x);
    }
    cout << "Verified intersection: "; for(auto x: intersection) cout << x << " "; cout << '\n';

    cout << "Simulation done." << endl;
    return 0;
}
