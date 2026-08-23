# FeUPSU: Build, Deployment, and Experiment Guide

FeUPSU is an experimental private set union (PSU) platform built with Microsoft SEAL, libOTe, and an OSN implementation. It includes reproducible Release-build helpers, Linux network emulation, batch benchmarks, result collection, and plotting utilities.

## Recommended deployment

Run the Client and Server on the same x86-64 Linux host and communicate over TCP through the loopback interface. Apply `tc netem` to `lo` to emulate LAN and WAN conditions. This avoids opening protocol ports to the public Internet and keeps public-network jitter out of the measurements.

| Resource | Recommendation |
| --- | --- |
| OS | Ubuntu Server 22.04 or 24.04 LTS, x86-64 |
| CPU | At least 16 vCPUs; 32 or more recommended |
| Memory | At least 64 GiB; 128 GiB recommended |
| Storage | At least 80 GiB SSD |
| Privileges | A sudo user; `tc netem` requires `CAP_NET_ADMIN` |

Large experiments require substantially more resources. In particular, `server_set=2^30` derives a very large bin-load parameter and may require extreme CPU time and memory. Start with `2^18`, then scale gradually while monitoring `free -h`, `vmstat 1`, and `htop`. Swap is not a substitute for sufficient physical memory.

Some auxiliary phases still assume loopback addresses and fixed ports. A two-host deployment requires additional changes to callback addresses, ports 39002--39009, firewall rules, transport security, and access control.

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

Clone all nested dependencies:

```bash
git clone --recurse-submodules <repository-url> psu-workspace
cd psu-workspace
git submodule update --init --recursive
```

For an uploaded archive, make sure these directories are populated:

```text
FeUPSU/libOTe/cryptoTools/
FeUPSU/osn/
```

A shared vcpkg installation next to `FeUPSU/` is recommended:

```bash
git clone https://github.com/microsoft/vcpkg.git vcpkg
./vcpkg/bootstrap-vcpkg.sh -disableMetrics
./vcpkg/vcpkg install \
  'seal[zlib,zstd,ms-gsl]' ms-gsl zstd span-lite libsodium \
  boost-system boost-thread boost-regex
```

The Microsoft GSL port is named `ms-gsl`, not `microsoft-gsl`. Initial vcpkg builds can take a long time, so retain its binary cache or disk snapshot when recreating cloud instances.

## Release build

From a workspace containing both `FeUPSU/` and `vcpkg/`:

```bash
VCPKG_ROOT="$PWD/vcpkg"

cmake -S FeUPSU/src -B FeUPSU/build -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DSEAL_DIR="$VCPKG_ROOT/installed/x64-linux/share/seal" \
  -DMicrosoft.GSL_DIR="$VCPKG_ROOT/installed/x64-linux/share/Microsoft.GSL" \
  -Dzstd_DIR="$VCPKG_ROOT/installed/x64-linux/share/zstd"

cmake --build FeUPSU/build -j "$(nproc)"
```

Check the resulting executables:

```bash
test -x FeUPSU/build/main
test -x FeUPSU/build/feupsu_client
test -x FeUPSU/build/feupsu_server
ldd FeUPSU/build/feupsu_client | grep 'not found' && exit 1 || true
```

If vcpkg is installed at `/home/jrj/code/vcpkg`, the repository helpers can be used directly:

```bash
cd FeUPSU
scripts/configure.sh --type Release
scripts/build.sh --type Release
```

`scripts/configure.sh` currently contains the development-machine vcpkg path and does not read `VCPKG_ROOT`. Use the explicit CMake command above or update the script when deploying elsewhere.

## Independent Client and Server processes

The following smoke test uses 32-bit elements, `hw=6`, one BFV batching vector on the Client, and effective bit length `32-log2(8192)=19`:

```bash
cd FeUPSU
mkdir -p results

./build/feupsu_server >results/feupsu_server.log 2>&1 &
FEUPSU_SERVER_PID=$!

for i in $(seq 1 50); do
  ss -ltn | grep -q ':39002 ' && break
  sleep 0.1
done

PSU_RESULTS_FILE=results/cloud_smoke.csv \
./build/feupsu_client \
  --server-host 127.0.0.1 \
  --server-set $((1<<18)) \
  --client-set $((1<<13)) \
  --effective-bitlength 19 \
  --hamming-weight 6

kill "$FEUPSU_SERVER_PID"
wait "$FEUPSU_SERVER_PID" 2>/dev/null || true
```

The main PSU service uses TCP 39002 and the masked-result phase uses TCP 39003. `circuitPSU` uses 39007 for control, 39008 for IKNP OT, and 39009 for the secret-shared shuffle. Cardinality refresh/finalization also uses the control service. These ports do not need to be opened in the cloud firewall for a same-host deployment.

```bash
ss -ltnp | grep -E ':3900[2-9] '
```

Set the same `FEUPSU_PORT_BASE` on both processes to move the complete port range. It uses `base` through `base+7`. If `--server-port` is also supplied, it must match `FEUPSU_PORT_BASE`.

### Protocol tasks

- `PSU`: end-to-end private set union with secret-shared output.
- `PSUca_C`: union cardinality is recovered only by the Client.
- `PSUca_S`: union cardinality is recovered only by the Server.
- `circuitPSU`: encrypted indicator generation followed by OT and a secret-shared OSN shuffle.

Example cardinality run:

```bash
# Terminal 1
./build/feupsu_server

# Terminal 2; replace PSUca_C with PSUca_S for Server output
./build/feupsu_client --task PSUca_C \
  --server-host 127.0.0.1 \
  --server-set $((1<<18)) \
  --client-set $((1<<13)) \
  --effective-bitlength 19 \
  --hamming-weight 6
```

Both cardinality variants use two independent per-slot one-time pads. The first pad safely permits the Client to refresh the noise-exhausted EEQ ciphertext. The Server removes it, adds a fresh final pad, performs a genuine Fisher--Yates BFV slot permutation with plaintext selectors and Galois rotations, and returns the shuffled ciphertext. `PSUca_C` removes the aggregate mask at the Client; `PSUca_S` returns the masked sum for Server-side recovery. The current permutation requires `client_set` to equal the selected `poly_modulus_degree`, as used by the provided cardinality batch script.

`effective-bitlength` is the input width of the constant-weight encoder, not the BFV plaintext-modulus width. BFV uses an approximately 20-bit batching prime. The benchmark generators still use `uint64_t` indices; a script labelled "128-bit" selects parameters derived for that scenario but does not itself load arbitrary 128-bit application records.

Example `circuitPSU` run:

```bash
# Terminal 1
FEUPSU_SERVER_SHARE_FILE=results/circuit_server.share \
./build/feupsu_server

# Terminal 2
FEUPSU_CLIENT_SHARE_FILE=results/circuit_client.share \
./build/feupsu_client --task circuitPSU \
  --server-host 127.0.0.1 \
  --server-set $((1<<18)) \
  --effective-bitlength 19 \
  --hamming-weight 6
```

Share files contain a `uint64_t` count followed by that many `uint64_t` values. XORing the two files reconstructs the commonly shuffled output. The logical input is the deduplicated Client-bin vector plus all Server elements, padded to the next power of two for the Benes/OSN network. Elements are shifted left by 10 bits before sharing. The complete circuit cost grows linearly with `server_set`; begin with `2^18` or less.

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

Batch scripts acquire sudo credentials once, keep them alive, and remove the qdisc on exit or a handled signal. Use `lo` for same-host experiments:

```bash
NETEM_IFACE=lo bash scripts/run_client_server_net_batch.sh
```

`run.sh` launches the integrated `build/main` executable. It contains Client and Server objects in one process but still exchanges protocol messages over loopback TCP. Use the standalone executables or the dedicated two-process script when strict process isolation is required.

After an abnormal termination:

```bash
sudo tc qdisc del dev lo root 2>/dev/null || true
```

Do not apply a restrictive WAN profile to the public interface carrying the current SSH session.

## Batch experiments

| Script | Purpose |
| --- | --- |
| `run_effective_hw_batch_custom.sh` | PSU experiments for selected 32/128-bit parameters and four network profiles. |
| `run_client_server_net_batch.sh` | Client-cardinality comparison under LAN/WAN profiles. |
| `run_psu_cardinality_batch.sh` | `PSUca_C` and `PSUca_S` cardinality experiments. |
| `run_circuit_psu_batch.sh` | LAN-only circuit-PSU experiments. |
| `run_two_process_psu_batch.sh` | Strictly independent Client and Server processes. |

`run_circuit_psu_batch.sh` with `server_set=2^22` pads the shuffle to roughly `2^23` inputs and constructs approximately 188.7 million Benes switches. It can require tens of GiB of peak memory. Resume supported scripts with:

```bash
RESUME=1 NETEM_IFACE=lo bash scripts/run_circuit_psu_batch.sh
```

## Result metrics (schema version 2)

Times are in milliseconds and communication counters are in bytes.

- `time_setup`, `comm_setup`: cryptographic setup and serialized parameters, relinearization/Galois keys, and the Client public key.
- `time_offline_comp`: both parties' encoding/batching plus Client query encryption. `time_offline` is a compatibility alias.
- `time_offline_comm`, `comm_offline`: encrypted batched query transfer.
- `time_online_comp`: the sum of protocol-required online computation by both parties; it is not wall-clock time when work overlaps.
- `time_online_comm`, `comm_online`: online network time and physical payload bytes, excluding Server computation from blocking receive time.

For `PSU`, online metrics cover Server EEQ/indicator/encrypted shares, Client decryption, inverse-indicator construction, encrypted slot permutation, segmented plaintext element multiplication, and final Server decryption.

For `PSUca_C/S`, online metrics also include blinded refresh, arbitrary BFV slot permutation, final mask handling, decryption, summation, and the optional Client-to-Server scalar return. Diagnostic fields include `time_psuca_permutation`, `time_psuca_refresh_ms`, and `comm_psuca_refresh`.

For `circuitPSU`, online metrics cover EEQ, indicator/share refresh, OT, and the actual OSN/Permute+Share computation and communication.

Fields such as `time_server`, `time_extract_response`, `comm_request`, and `comm_response` are diagnostic subphases and may overlap the canonical totals. Do not add them to the phase totals again.

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/` | Core implementation and CMake project. |
| `libOTe/`, `osn/` | OT and OSN dependencies. |
| `scripts/` | Configure, build, run, and batch helpers. |
| `experiments/` | Experiment configuration, aggregation, and plotting. |
| `results/` | CSV results. |
| `build/` | Generated build tree and executables. |

## Troubleshooting

1. **vcpkg or SEAL not found:** verify the toolchain and `*-DIR` paths, then install any missing packages with the vcpkg command above.
2. **Port already in use:** inspect `ss -ltnp`, terminate the stale process, or assign a new `FEUPSU_PORT_BASE` to both parties.
3. **`tc` permission error:** run `sudo -v`, grant narrowly scoped permission for `tc`, or use `--profile off`.
4. **Missing `compile_commands.json`:** re-run `scripts/configure.sh` or CMake with `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`.
5. **Large circuit experiment fails:** monitor memory, resume completed cases, and reduce `server_set` before increasing the instance size.

Record the instance type, CPU and memory, compiler version, Git revision, Release configuration, network profile, and repetition count for every reported experiment. Do not run competing benchmarks concurrently on the same host.
