# UPSICA: VBF + Slicing

This directory implements the receiver-output uPSI-CA protocol from Wu and
Yuen, *Efficient Unbalanced Private Set Intersection* (USENIX Security 2023),
using the paper's VBF+slicing variant.

The implemented functionality is:

- Sender input: large set `X`.
- Receiver input: small set `Y`.
- Receiver output: `|X intersection Y|` (and locally derived union cardinality).
- Sender output: nothing.

It is functionally comparable with `FeUPSU task=PSUca_C`. It is not a
replacement for `PSUca_S`, whose output party is different.

## Protocol implemented

1. Sender offline-preprocesses `X` with its OPRF key, `kv`-way VBF encoding,
   three-choice Simple Hashing, alpha sub-bins, slicing, and one ordinary root
   polynomial for every `(bin, sub-bin, slice)`.
2. Receiver blinds the entire OPRF batch with one common DH exponent `beta`.
   Sender evaluates and secretly shuffles the responses; no permutation is
   returned. Receiver unblinds the anonymous responses with `beta^-1`.
3. Receiver VBF-encodes the anonymous tokens and inserts every VBF sub-item in
   exactly one of the same three candidate bins using Cuckoo Hashing.
4. Receiver generates BFV keys and sends only the public/relinearization keys
   and encrypted SIMD query powers. The table is split into as many SIMD chunks
   as needed; it is not forced to fit in one polynomial degree.
5. Sender evaluates its plaintext root polynomials without a secret key and
   returns ciphertexts.
6. Receiver decrypts. A VBF sub-item matches only when all slices are zero in
   the same Sender sub-bin. An anonymous OPRF token matches only when all `kv`
   VBF sub-items match. Receiver counts matching tokens.

The wire contains only blinded EC points, shuffled evaluated points, BFV
evaluation keys, query ciphertexts, and result ciphertexts. Raw Receiver
elements, the OPRF key, plaintext Sender polynomials, and the BFV secret key are
never serialized.

The current first implementation sends every encrypted power from `1` through
the public polynomial-degree bound, as permitted by the paper's non-windowed
baseline. This is correct but communication-heavy. A powers DAG/window-set
optimization can reduce query communication without changing the protocol.

## Build

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DUPSICA_ENABLE_APSI=OFF \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build -j
ctest --test-dir build --output-on-failure
```

The bundled `APSI-main/` tree is retained only as a reference and is disabled
by default. The VBF+slicing implementation does not link APSI, so Kuku,
Flatbuffers, and jsoncpp are not required to build `upsica-vbf`.

## Run two independent processes

Server:

```bash
./build/upsica-vbf --role server --port 19090 \
  --sender-set 262144 --receiver-set 8192 --intersection 16 \
  --element-bits 32 --bins 32768 --alpha 4 --poly-degree 8192 \
  --results results/server.csv
```

Receiver:

```bash
./build/upsica-vbf --role client --host 127.0.0.1 --port 19090 \
  --sender-set 262144 --receiver-set 8192 --intersection 16 \
  --element-bits 32 --bins 32768 --alpha 4 --poly-degree 8192 \
  --results results/client.csv
```

The same executable supports actual 128-bit elements using 16-byte item
buffers; 128-bit mode is not truncated to `uint64_t`.

Benchmark inputs are constructed injectively: the first `--intersection`
Receiver items are shared with Sender and all remaining Receiver items are
chosen immediately outside the Sender range. Thus the measured cardinality is
exactly controlled even for a (2^{22}) Sender in the 32-bit universe; random
32-bit birthday collisions cannot create unplanned matches.

Merge the two role-local metric files:

```bash
scripts/merge_metrics.sh results/server.csv results/client.csv results/run.csv
```

Run the full LAN/WAN batch with persistent sudo credentials and resume support:

```bash
sudo -v
RESUME=1 bash scripts/batch.sh
```

## Metrics and comparison with FeUPSU PSUca_C

Merged files use FeUPSU-style `key,value` rows:

- `time_setup`: Sender OPRF key generation plus Receiver BFV key generation.
- `comm_setup`: BFV public and relinearization keys carried at the start of the
  FHE query. These bytes are excluded from `comm_online` and included once in
  `comm_total`.
- `time_offline_comp`: Sender-only OPRF/VBF/hash/sub-bin/polynomial preprocessing.
- `time_offline_comm`, `comm_offline`: zero, because UPSICA Sender preparation
  is non-interactive.
- `time_online_comp`: both parties' OPRF, query construction/encryption,
  homomorphic evaluation, decryption, and cardinality computation.
- `time_online_comm`: online wall time minus measured setup and both parties'
  online computation. This retains network throttling/latency but removes the
  remote computation wait.
- `comm_online`: physical bytes for both OPRF messages and both FHE messages,
  including framing and evaluation keys.

For a fair end-to-end comparison with `PSUca_C`, compare identical element
lengths, public set sizes, intersection construction, BFV security parameters,
hardware, Release builds, and network shaping. Phase-by-phase values must still
be interpreted according to each protocol: UPSICA deliberately moves all
Sender preprocessing into its offline phase, whereas FeUPSU's offline phase has
different work. Total computation and total communication are directly
comparable; an isolated offline/online ratio is not a protocol-independent
metric.
