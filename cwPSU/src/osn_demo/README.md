# OSN Demo

This example shows how to use the repository's `OSNSender` and `OSNReceiver`
from a standalone program to execute a minimal Oblivious Shuffle Network
(Permute+Share) protocol.

## Contents

```text
osn_demo/
├── CMakeLists.txt
├── main.cpp      # Example implementation
└── README.md     # Usage guide
```

`main.cpp` demonstrates how to:

1. construct a local input vector;
2. connect the Sender and Receiver with `Session` and `Channel` objects;
3. initialize `OSNSender` and `OSNReceiver` and call `run_osn`;
4. XOR the two output shares and verify the permuted result.

## Build and run

Configure and build the repository and its dependencies first:

```bash
cmake -S src -B build
cmake --build build --target osn_demo
```

The default run uses (2^4=16) elements, one channel, and IKNP OT
(`ot_type=1`). Run the executable from the build directory:

```bash
./osn_demo            # Default parameters
./osn_demo 10 2       # 2^10 elements and two parallel channels
./osn_demo 10 2 2     # Silent OT; requires/generated cache data
```

With `ot_type=2`, the program creates cache files whose names start with
`osn_demo_cache_` in the current directory. Later runs reuse those files.

## Reusing the demo in another project

1. Copy `osn/` and this example's `main.cpp`, and add libOTe/cryptoTools as
   build dependencies.
2. Enable `ENABLE_BOOST`, add libOTe with `add_subdirectory(libOTe)`, and link
   the target against `osn`, `libOTe`, and `cryptoTools`.
3. Add include paths for `osn/` and
   `libOTe/out/install/<preset>/include`.
4. Construct an `IOService`, `Session`, and `Channel` set for each party.
5. Call `OSNSender::init(size, ot_type, cache_prefix)` and
   `OSNReceiver::init(size, ot_type)`, then run both parties to obtain shares.
6. Use `sender.dest` to inspect the random permutation or XOR corresponding
   shares to reconstruct the permuted values.

See `osn_demo/main.cpp` for the complete example.
