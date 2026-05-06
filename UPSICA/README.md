# UPSICA

UPSICA is a scaffold for reproducing the unbalanced private set intersection cardinality (UPSICA) scheme from Wu & Yuen. It mirrors the paper’s modules and separates offline preparation from online query.

## Structure

- `src/CryptoPrimitives`: Shuffled DH-OPRF + SEAL wrapper (BFV/CKKS placeholders).
- `src/DataStructure`: VBF, hashing (cuckoo/simple), polynomial links.
- `src/Protocol`: Preparation + Online phases.
- `include/upsica`: Public headers.

## Build (SEAL + local APSI-main)

```bash
cmake -S . -B build -G Ninja
cmake --build build
```

`UPSICA` now auto-enables:

- `UPSICA_ENABLE_APSI=ON` if `APSI-main/` exists under this project.
- `UPSICA_ENABLE_SEAL=ON` by default.

If SEAL is installed via vcpkg, configure with toolchain (recommended):

```bash
cmake -S . -B build -G Ninja \
	-DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build
```

If CMake still cannot find SEAL, pass `SEAL_DIR` explicitly:

```bash
cmake -S . -B build -G Ninja \
	-DSEAL_DIR=/path/to/vcpkg/installed/x64-linux/share/seal
cmake --build build
```

If APSI source is not in `APSI-main/`, set path manually:

```bash
cmake -S . -B build -G Ninja \
	-DUPSICA_APSI_SOURCE_DIR=/absolute/path/to/APSI
cmake --build build
```

## Next steps

1. Implement real SEAL operations in `FheWrapper` (encode/encrypt/eval/decrypt).
2. Replace stub DH-OPRF flow with APSI/FourQ-backed primitives.
3. Fill in VBF, hashing, and polynomial-link logic.
4. Implement protocol orchestration with sender/user roles and metrics export.

If you want, tell me the APSI path under `CODE/` and I will link it in CMake and stub the interfaces.
