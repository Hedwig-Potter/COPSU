# cwPSU · 运行与实验指南

代码对应论文《PEPSI: Practically Efficient Private Set Intersection in the Unbalanced Setting》（USENIX Security 2024）。本仓库提供 cwPSU 主实现、OSN/OT 依赖与若干实验脚本。本文档聚焦“如何运行”：从准备依赖、构建、执行单次或批量实验，到收集结果与排查常见问题。
## 目录结构概览

| 路径 | 说明 |
| --- | --- |
| `src/` | cwPSU/PEPSI 主实现与 `main-*` / `main-cwpsu` 可执行入口。 |
| `libOTe/`, `osn/` | OT/OSN 依赖源代码，通过 CMake `add_subdirectory` 编译。 |
| `scripts/` | 运行脚本 (`run.sh`, `run_batch.sh`) 及网络仿真封装。 |
| `experiments/` | 纯 OpenMP/C++ 实验程序与绘图/分析脚本。 |
| `results/`, `run.log` | 批量实验记录与输出 CSV。 |
| `build/` | CMake 生成目录，包含 `main-cwpsu`, `main-base`, `main2`, `osn_demo` 等二进制与 `compile_commands.json`。 |
| `vcpkg/` | 建议放置 vcpkg 副本并安装全部第三方依赖（SEAL/GSL/zstd 等）。 |

## 先决条件

1. **系统工具**
	- CMake ≥ 3.16，推荐配合 Ninja (`cmake -G Ninja`)。
	- GCC ≥ 10 或 Clang ≥ 12，完整支持 C++17 与 OpenMP。
	- Python 3（用于少量辅助脚本，可选）。

2. **第三方库**
	- Microsoft SEAL
	- Microsoft GSL、zstd、span-lite（由 vcpkg 解决）
	- libsodium（libOTe 的 SimplestOT/SilentOT 需要）

3. **vcpkg（推荐）**
	- 仓库内已经自带 `cwPSU/vcpkg/`，也可使用全局安装。若路径不同，请将 `VCPKG_ROOT` 指向你的安装目录，或修改 `src/CMakeLists.txt` 中的 `CMAKE_TOOLCHAIN_FILE`。

## 初始化仓库

```bash
git clone <repo> cwPSU
cd cwPSU
git submodule update --init --recursive   # 拉取 libOTe、cryptoTools 等依赖
```

## 快速构建 main-cwpsu

> `scripts/run.sh` 默认在 `build/main-cwpsu` 查找二进制，因此推荐直接将构建目录设为 `build/`。

```bash
cmake -S src -B build \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=$(pwd)/vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DSEAL_DIR=$(pwd)/vcpkg/installed/x64-linux/share/SEAL \
  -DMicrosoft.GSL_DIR=$(pwd)/vcpkg/installed/x64-linux/share/Microsoft.GSL \
  -Dzstd_DIR=$(pwd)/vcpkg/installed/x64-linux/share/zstd

cmake --build build -j
```

构建完成后你会得到：

- `build/main-cwpsu`: cwPSU 主程序（默认启用 SEAL、OpenMP、OSN）。
- `build/main-base`, `build/main2`: 其他实验入口（同样依赖 SEAL）。
- `build/osn_demo`: OSN 单独演示程序。
- `build/libOTe/*`: OT/OSN 依赖生成产物。
- `build/compile_commands.json`: IDE/静态分析可用的编译数据库。

## 运行单次实验

脚本 `scripts/run.sh` 提供网络仿真封装 (tc netem) 并执行 `main-cwpsu`：

```bash
scripts/run.sh \
  --profile lan \
  --iface lo \
  -- \
  --server_set $((1<<20)) \
  --effective_bitlength 114 \
  --hamming_weight 19
```

参数说明：

| 参数 | 作用 |
| --- | --- |
| `--profile` | 选择网络配置：`lan`、`wan-100`、`wan-10`、`wan-1` 或 `off` (仅清理 netem)。若省略则默认 `NETEM_PROFILE` 或 `native`。 |
| `--iface` | 指定应用 netem 的网卡，默认 `NETEM_IFACE` 或 `lo`。非 root 用户运行时会自动通过 `sudo tc`。 |
| `--` | 之后的参数将原样传递给 `main-cwpsu`。常用参数：`--server_set <N>`、`--effective_bitlength <bits>`、`--hamming_weight <hw>`。 |

脚本在启动时会配置 `tc qdisc`，退出时自动清理；也可以显式执行 `scripts/run.sh --profile off` 清除残留设置。

## 批量跑全配置

`scripts/run_batch.sh` 预设了若干网络 profile、服务器集合大小（2^18/2^20/2^22）以及 `(bitlength, hamming_weight)` 组合，会循环调用 `scripts/run.sh`：

```bash
NETEM_IFACE=lo scripts/run_batch.sh
```

脚本结束时会自动清除 netem。所有运行输出（包括 cwPSU 程序自身日志）可在 `run.log` 或你指定的输出重定向中查看，性能数据可写入 `results/`。

## 编译 OpenMP 实验程序

`experiments/` 目录下的 `script.cpp` 不依赖 SEAL，只需 OpenMP：

```bash
cmake -S experiments -B build/experiments
cmake --build build/experiments -j
```

生成的 `build/experiments/script` 可用于轻量模拟或与 `experiments/*.py` 配合绘图。

## 结果与分析

- `results/`: 保存论文表格/图中使用的 CSV。
- `osn_demo_cache_16/`: 预生成的 OSN 数据，`osn_demo` 可直接消费。
- `run.log`: `scripts/run.sh` 默认会将 stdout/stderr 同步到该文件（可按需重定向）。

`experiments/compare.py`、`experiments/plots.ipynb` 等脚本可将 `results/` 中的数据绘图或与其他实现比较。

## 常见问题排查

1. **`Binary not found: build/main-cwpsu`**：确认 `cmake -S src -B build`，并使用与脚本一致的 `build/` 输出目录；若放在其他目录需手动修改 `scripts/run.sh` 中的路径。
2. **`SEAL not found`**：确保 vcpkg 安装 `seal`，并在 configure 阶段提供 `-DCMAKE_TOOLCHAIN_FILE` 或 `-DSEAL_DIR`。运行 `vcpkg install seal microsoft-gsl zstd libsodium` 以安装缺失依赖。
3. **`tc: permission denied`**：网络仿真需 root；可预先 `sudo scripts/run.sh --profile lan ...`、配置无密码 sudo，或直接跳过 netem (`--profile off`)。
4. **OpenMP 未启用**：确认编译器支持 `-fopenmp` (GCC) 或 `-fopenmp`/`-qopenmp` (Clang/ICC)。CMake 日志里寻找 `Found OpenMP` 字样。
5. **编译速度慢 / 内存占用高**：可将 `ENABLE_AVX` 打开以获得更快运行，也可在 `cmake --build` 时附加 `-j <N>` 控制并发。

## 进一步定制

- 若需在 Docker/CI 中构建，可将前述 `cmake` 命令写入脚本再挂载 `vcpkg` 缓存。
- 可以通过 `-DCMAKE_BUILD_TYPE=RelWithDebInfo` 在保证性能的同时保留调试符号。
- 如果你维护不同的 vcpkg triplet（如 `x64-linux-release`），将 `-DCMAKE_TOOLCHAIN_FILE` 指向相应路径，并同步调整 `*-DIR` 变量。

如在运行过程中遇到问题，可在 `run.log`、`build/CMakeFiles/CMakeOutput.log` 或 `results/*.csv` 中查找线索，或配合 `VERBOSE=1 cmake --build build` 观察完整编译命令。