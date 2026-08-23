# cwPSU: Build, Deployment, and Experiment Guide

This repository contains the cwPSU implementation, its OT/OSN dependencies,
and experiment scripts used for comparison with FeUPSU. The implementation is
based on the constant-weight techniques used by PEPSI, *Practically Efficient
Private Set Intersection in the Unbalanced Setting* (USENIX Security 2024).

## Recommended deployment

Run `cwpsu-client` and `cwpsu-server` as independent processes on the same
x86-64 Ubuntu host. They communicate through loopback TCP, while `tc netem` on
`lo` emulates LAN and WAN environments. This avoids exposing protocol ports to
the Internet and prevents public-network jitter from affecting the benchmark.

| Resource | Recommendation |
| --- | --- |
| OS | Ubuntu Server 22.04 or 24.04 LTS, x86-64 |
| CPU | At least 16 vCPUs; 32 or more recommended |
| Memory | At least 64 GiB; 128 GiB recommended |
| Storage | At least 80 GiB SSD |
| Privileges | A sudo user; `tc netem` requires `CAP_NET_ADMIN` |

Experiments with `server_set=2^30` can consume substantial CPU time and memory.
Validate the environment with `2^18` first, then scale gradually while using
`free -h`, `vmstat 1`, and `htop`. Do not treat swap as a replacement for
physical memory.

Permute+Share is an actual two-party OSN protocol: the Client supplies the
permutation, the Server supplies the random vector, and neither party learns
the other's private input. Same-host runs use ports 39001--39004. A two-host
deployment additionally requires `PSU_PERMUTE_HOST`, firewall configuration,
transport protection, and access control.

## System dependencies

```bash
sudo apt update
sudo apt install -y \
  build-essential cmake ninja-build git curl zip unzip tar pkg-config \
  autoconf automake autoconf-archive libtool \
  python3 python3-pip iproute2 libsodium-dev
```

Verify the main tools:

```bash
cmake --version
g++ --version
ninja --version
tc -V
```

## Source tree and vcpkg

Clone nested dependencies:

```bash
git clone --recurse-submodules <repository-url> psu-workspace
cd psu-workspace
git submodule update --init --recursive
```

For an uploaded archive, verify that `cwPSU/libOTe/cryptoTools/` and
`cwPSU/osn/` are populated.

cwPSU can use its bundled `cwPSU/vcpkg/` tree or a shared vcpkg installation at
the workspace root. A shared installation can be prepared with:

```bash
git clone https://github.com/microsoft/vcpkg.git vcpkg
./vcpkg/bootstrap-vcpkg.sh -disableMetrics
./vcpkg/vcpkg install \
  'seal[zlib,zstd,ms-gsl]' ms-gsl zstd span-lite libsodium \
  boost-system boost-thread boost-regex
```

The Microsoft GSL port is `ms-gsl`. Preserve the vcpkg binary cache or disk
snapshot to avoid rebuilding all dependencies on every cloud instance.

## Release build

From a workspace containing `cwPSU/` and `vcpkg/`:

```bash
VCPKG_ROOT="$PWD/vcpkg"

cmake -S cwPSU/src -B cwPSU/build -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DSEAL_DIR="$VCPKG_ROOT/installed/x64-linux/share/seal" \
  -DMicrosoft.GSL_DIR="$VCPKG_ROOT/installed/x64-linux/share/Microsoft.GSL" \
  -Dzstd_DIR="$VCPKG_ROOT/installed/x64-linux/share/zstd"

cmake --build cwPSU/build -j "$(nproc)"
```

If the bundled vcpkg tree is used, set `VCPKG_ROOT="$PWD/cwPSU/vcpkg"` instead.

Check the executables:

```bash
test -x cwPSU/build/main-cwpsu
test -x cwPSU/build/cwpsu-client
test -x cwPSU/build/cwpsu-server
ldd cwPSU/build/cwpsu-client | grep 'not found' && exit 1 || true
```

Other generated targets may include `main-base`, `main2`, `osn_demo`, and the
libOTe build products.

## Running independent Client and Server processes

This smoke test uses 32-bit elements, `hw=7`, one BFV batching vector on the
Client, and effective bit length `32-log2(8192)=19`:

```bash
cd cwPSU
mkdir -p results

./build/cwpsu-server >results/cwpsu_server.log 2>&1 &
CWPSU_SERVER_PID=$!

for i in $(seq 1 50); do
  ss -ltn | grep -q ':39002 ' && break
  sleep 0.1
done

PSU_RESULTS_FILE=results/cloud_smoke.csv \
./build/cwpsu-client \
  --server-host 127.0.0.1 \
  --server-set $((1<<18)) \
  --client-set $((1<<13)) \
  --effective-bitlength 19 \
  --hamming-weight 7

kill "$CWPSU_SERVER_PID"
wait "$CWPSU_SERVER_PID" 2>/dev/null || true
```

cwPSU uses TCP 39001 for Permute+Share control, 39002 for the main PSU
service, 39003 for the masked phase, and 39004 for OSN data. These ports do not
need to be exposed by the cloud firewall for same-host deployment.

```bash
ss -ltnp | grep -E ':3900[1-4] '
```

## Protocol outline

1. Client and Server encode and batch their constant-weight representations.
2. Client encrypts its batched query and sends it to the Server.
3. During the offline phase, the Client supplies a permutation and the Server
   supplies a random vector to Permute+Share. They receive additive shares of
   the permuted vector.
4. Server evaluates EEQ, constructs the encrypted indicator and inverse
   indicator, and adds the random vector used by Permute+Share.
5. Server sends the masked ciphertext and the encrypted Server share.
6. Client applies the same permutation to the ciphertext slots, subtracts its
   own share and the encrypted Server share, permutes the elements, splits
   elements that exceed the plaintext modulus, and performs ciphertext--plain
   multiplication.
7. Client returns the encrypted masked elements, and Server decrypts the set
   difference output.

## Network emulation

Check kernel support:

```bash
sudo modprobe sch_netem
sudo tc qdisc replace dev lo root netem delay 1ms
sudo tc qdisc del dev lo root
```

| Profile | Rate | One-way delay | Approximate RTT |
| --- | ---: | ---: | ---: |
| `lan` | 10 Gbit/s | 0.1 ms | 0.2 ms |
| `wan-100` | 100 Mbit/s | 40 ms | 80 ms |
| `wan-10` | 10 Mbit/s | 40 ms | 80 ms |
| `wan-1` | 1 Mbit/s | 40 ms | 80 ms |

Batch scripts acquire sudo credentials once, keep them alive, and remove the
qdisc at exit. Use the loopback interface for same-host experiments:

```bash
cd cwPSU
NETEM_IFACE=lo bash scripts/run_client_server_net_batch.sh
```

Some batch helpers call the integrated `build/main-cwpsu` entry point. That
entry point contains both parties in one process but still uses loopback TCP.
Use `cwpsu-client` and `cwpsu-server` directly when strict process isolation is
required.

After an abnormal termination:

```bash
sudo tc qdisc del dev lo root 2>/dev/null || true
```

Never apply a restrictive WAN profile to the public interface carrying the
active SSH connection.

## Batch experiments

```bash
NETEM_IFACE=lo bash scripts/run_effective_hw_batch.sh
NETEM_IFACE=lo bash scripts/run_client_server_net_batch.sh
```

The current effective-HW batch uses the selected protocol parameters for
32-bit and 128-bit scenarios. Scripts write CSV files to `results/`, keep sudo
credentials alive for `tc`, and clean up network shaping on exit. Do not run
cwPSU and FeUPSU benchmarks concurrently when comparing them.

The lightweight OpenMP experiment under `experiments/` can be built separately:

```bash
cmake -S experiments -B build/experiments
cmake --build build/experiments -j
```

## Result metrics (schema version 2)

Times are in milliseconds and communication counters are in bytes.

- `time_setup`, `comm_setup`: Client key/context generation, serialized
  parameters and evaluation keys, and Server-side loading/setup.
- `time_offline_comp`: both parties' encoding and batching, Client query
  encryption, and both parties' Permute+Share computation.
- `time_offline_comm`, `comm_offline`: encrypted query transfer and the
  Permute+Share control/OSN traffic.
- `time_online_comp`: Server EEQ, indicator/inverse-indicator construction,
  random-vector addition and encrypted share preparation; Client decryption,
  encrypted permutation, share removal, segmented plaintext multiplication;
  and final Server decryption.
- `time_online_comm`, `comm_online`: Server-to-Client masked ciphertext/share
  response and Client-to-Server final encrypted product.

`time_permute_share_client_compute_us` and
`time_permute_share_server_compute_ms` use thread CPU time where possible.
`time_permute_share_network_ms` is wall time, while
`time_permute_share_comm_ms` subtracts the critical-path computation estimate.

Diagnostic fields such as `time_server`, `time_extract_response`,
`time_permute_share_network_ms`, `comm_request`, and `comm_response` overlap the
canonical phase totals. Do not sum them a second time.

## Fair comparison with FeUPSU

Use the same instance type, compiler, Release configuration, thread policy,
element length, Client and Server cardinalities, intersection construction,
repetition count, and `tc` profile. Compare the canonical setup/offline/online
metrics from schema version 2. cwPSU deliberately performs Permute+Share in its
offline phase, so phase-level differences should be interpreted together with
the protocol definitions; total computation and total communication provide
the most direct end-to-end comparison.

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/` | Main cwPSU implementation and executable entry points. |
| `libOTe/`, `osn/` | OT and OSN source dependencies. |
| `scripts/` | Run, network emulation, and batch helpers. |
| `experiments/` | Lightweight experiments and plotting utilities. |
| `results/` | Experiment CSV files. |
| `build/` | Generated CMake build tree and executables. |
| `vcpkg/` | Optional bundled vcpkg installation. |

## Troubleshooting

1. **`build/main-cwpsu` not found:** configure with `cmake -S src -B build` so
   the output directory matches the scripts.
2. **SEAL not found:** verify `CMAKE_TOOLCHAIN_FILE` and `SEAL_DIR`, then
   install the dependencies listed above.
3. **`tc: permission denied`:** run `sudo -v`, configure narrowly scoped sudo
   permission, or use `--profile off`.
4. **OpenMP not enabled:** check the CMake output for `Found OpenMP` and use a
   compiler with OpenMP support.
5. **Slow build or high memory use:** limit build parallelism with
   `cmake --build build -j <N>`; enable only CPU features supported by the
   deployment host.

Record the Git revision, instance type, CPU and memory, compiler version,
Release configuration, network profile, and every raw CSV used in a reported
comparison.
