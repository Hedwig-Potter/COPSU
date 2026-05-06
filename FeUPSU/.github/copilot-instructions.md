# FeUPSU — AI agent quickstart

Purpose: make AI coding agents productive in this C++/CMake PSU (Private Set Union) project using Microsoft SEAL (BFV) and OpenMP.

## Architecture in 10 lines
- Single executable `build/main`; sources in `src/`.
- Roles live in-process: `Client` and `Server` exchange data via `std::stringstream` (no sockets yet).
- `Params` (in `utils.*`) derives HE params and protocol sizes from knobs: `mu`, `gamma`, `effective_lambda`, `hw`, `label_byte_size`.
- Flow (PSU): Client sets SEAL → sends params+keys → sends encrypted constant‑weight codes; Server computes indicator polys → sends back `shc_cts` (under client key) + `server_public_key` + `shs` (under server key).
- Client decrypts `shc_cts`, then combines with `shs` to compute `a + b − 2ab` under server key, digit‑decomposes values in base `p` and sends masked digits; Server decrypts digits and reconstructs values per bin.
- Key files: `src/main.cpp`, `src/client.*`, `src/server.*`, `src/utils.*`, `src/CMakeLists.txt`.

## Wire/serialization contracts (order matters)
- Client → Server (params_stream): `EncryptionParameters`, then `RelinKeys`, `GaloisKeys`, `PublicKey`.
- Client → Server (data_stream queries): `gamma*ell` ciphertexts (BFV, symmetric encrypt) in row‑major by `ell` per `gamma`.
- Server → Client (first response): `server_public_key`, then `gamma` `shc_cts`, then one `shs_encrypted_by_server`.
- Client → Server (masked digits): binary header `[K, D, m]` as three `uint64_t`, then `K × D` ciphertexts; slot `i` corresponds to bin `i`.
- Tip: Always clear streams when reusing: call `str("")` or create a new stream before writing a fresh payload.

## Build and run
- Scripts: `scripts/configure.sh` (CMake Debug + compile_commands), `scripts/build.sh`, `scripts/run.sh` (runs `build/main`).
- VS Code tasks mirror scripts: “Configure (cmake)”, “Build”, “Run”, “Build and Run”.
- Example: `scripts/configure.sh && scripts/build.sh && scripts/run.sh --mu 256 --gamma 2 --effective_bitlength 19 -x 1`.

## Parameters and performance
- `Params` sets BFV chain based on Hamming weight `hw`; see thresholds in `utils.cpp` (e.g., `hw <= 4` → `{60,48,48,60}` at N=8192). Change HE params only via `Params`.
- OpenMP: `main.cpp` sets `omp_set_num_threads(32)`; server hot loops use `#pragma omp parallel for` (some with `collapse(2)`). Avoid sharing mutable SEAL objects across threads.

## CMake, vcpkg, deps
- Requires CMake ≥ 3.16, g++ (C++20), OpenMP, Microsoft SEAL via vcpkg.
- `scripts/configure.sh` assumes vcpkg at `/home/jrj/code/vcpkg` and passes `-DCMAKE_TOOLCHAIN_FILE=...` plus `-D*DIR` hints; `src/CMakeLists.txt` also sets a toolchain path — keep these consistent if relocating vcpkg.
- Links: `SEAL::seal` and `OpenMP::OpenMP_CXX`.

## Gotchas specific to this repo
- Ensure a `results/` directory exists relative to the working dir; `Client::run_protocol` writes `results/<timestamp>.csv` but doesn’t create the folder.
- `num_cts` the client decrypts is task‑dependent: PSU=`gamma`, PSUCardinality/circuitPSU=`1`. Keep server/client in sync if you change outputs.
- There are two `send_results()` calls in `Server::do_server_computation`; mind stream position and clearing when modifying the pipeline.
- When changing wire format, update both writer and reader in lockstep; add comments near the write sites pointing to the matching reads.

## Good entry points
- New protocol step: extend `Server::do_server_computation` and mirror reads in `Client::load_and_decrypt`; record `time_*` and `comm_*` in `Metrics` (`utils.*`).
- Parameter tuning: adjust only `Params` in `utils.cpp`; avoid duplicating SEAL param logic elsewhere.
- Networking later: the existing `save/load` and `[K,D,m]+cts` layout define a transport‑agnostic format you can move to sockets/IPC.
