# FeUPSU 使用说明

FeUPSU 是一套基于 Microsoft SEAL、libOTe 与自研 OSN 组件的私集合并 (PSU) 实验平台，提供了完整的构建脚本、网络仿真脚本以及批量实验基准。本文档聚焦于“如何运行”——从准备依赖到执行单次或批量实验、收集结果的完整流程。

## 项目结构速览

| 目录 | 作用 |
| --- | --- |
| `src/` | 核心 PSU 实现与 `main`/`main2`/`test` 等可执行文件入口 (CMake 项目)。 |
| `libOTe/`, `osn/` | 第三方及自研 OT/OSN 组件源码，CMake 通过 `add_subdirectory` 拉入。 |
| `scripts/` | 一键配置、构建、运行与批量实验脚本。 |
| `experiments/`, `results/`, `results_dir/` | 记录实验配置、输出 CSV 以及绘图脚本。 |
| `build/` | 由 `scripts/configure.sh` 生成的构建目录，包含 `compile_commands.json` 与可执行文件。 |

## 运行所需的依赖

1. **系统工具**
	- CMake ≥ 3.16
	- Ninja (默认生成器，可改)
	- GCC 或 Clang，需完整支持 C++20/17（源码默认 `-std=c++17`）。
2. **vcpkg 依赖**
	- vcpkg 已安装，并位于 `scripts` 默认写死的路径 `/home/jrj/code/vcpkg`。
	- 安装包：`seal`, `microsoft-gsl`, `zstd`，以及 `libdivide`/`span-lite` 等通过 vcpkg 头文件提供的依赖。
	- 如需自定义路径，可在运行脚本前 `export VCPKG_ROOT=<your/path>`，或修改 `scripts/configure.sh` 中的 `VCPKG_ROOT`。
3. **可选**
	- `sudo` 权限：`scripts/run.sh` 在启用网络仿真 (tc netem) 时会调用 `sudo tc ...`。
	- Python 3：用于 `scripts/eeq_coeffs.py` 等实验脚本。

## 快速上手：一键构建与运行

在仓库根目录 `FeUPSU/` 执行：

```bash
scripts/configure.sh --type Release   # 可选：Debug/RelWithDebInfo/MinSizeRel
scripts/build.sh                      # 复用 configure 阶段的 build type
scripts/run.sh -- --effective_bitlength 114 --hw 32
```

脚本说明：

| 脚本 | 功能 | 常用参数 |
| --- | --- | --- |
| `scripts/configure.sh` | 调用 CMake 生成 `build/`，自动挂载 vcpkg toolchain、SEAL、GSL、zstd 路径。 | `--type <BuildType>` (默认 Debug) |
| `scripts/build.sh` | 在 `build/` 内执行 `cmake --build`，默认使用 Ninja。 | `--type <BuildType>`；不传则沿用上一次配置 |
| `scripts/run.sh` | 自动定位 `build/main` 或 `build/main2`，支持网络剖面仿真后执行 PSU 程序。 | `--profile <lan|wan-100|wan-10|wan-1|off>`、`--iface <nic>`、`--` 之后传递给程序的原生参数 |

> 提示：若使用 VS Code/CMake Tools，也可以直接将 `src/` 作为根项目导入；脚本只是复现相同步骤并预设依赖路径。

## 运行参数与网络仿真

`scripts/run.sh` 会尝试按照以下顺序查找可执行文件：`build/main` → `build/main2` → `src/build/main` → `src/build/main2`。若找不到会提示先运行 configure/build。

- `--profile`：为本地回环网卡 (默认 `lo`) 套用 `tc netem` 规则，模拟不同带宽/延迟；结束时自动清理。
- `--iface`：指定要注入 `tc` 规则的网卡。也可通过环境变量 `NETEM_IFACE` 为脚本设置默认值。
- `--`：之后的内容全部透传给 PSU 可执行文件，例如 `--nParties 2 --effective_bitlength 114 --hw 32`。

常见用法：

```bash
# 模拟局域网场景并运行 main
scripts/run.sh --profile lan -- --effective_bitlength 114 --hw 32

# 清除现有网络仿真设置
scripts/run.sh --profile off
```

若计划在非 root 用户下运行，需要确保 `sudo` 对 `tc` 有执行权限，或者预先在接口上配置好 `tc` 并使用 `--profile off`。

## 批量实验与结果

`scripts/` 目录提供了若干批量基准脚本（全部在运行前自动调用 `scripts/run.sh`）：

| 脚本 | 说明 |
| --- | --- |
| `run_batch.sh` | 读取预置参数集合，顺序跑完所有配置，并将输出写入 `results/`。 |
| `run_psu_cardinality_batch.sh` | 针对不同集合规模/有效比特的实验。 |
| `run_circuit_psu_batch.sh` | circuit-PSU 特定配置。 |
| `run_hw*.sh` | 针对论文中指定汉明重量 (HW) 组合的精确复现实验。 |

实验脚本通常会将 CSV 写入 `results/` 或 `results_dir/`。`experiments/compare.py`、`experiments/plots.ipynb` 可用于绘图与对比分析。

## 手动构建 (可选)

若你不想使用脚本，直接在 `src/` 下执行：

```bash
cmake -S . -B ../build -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=/home/jrj/code/vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DSEAL_DIR=/home/jrj/code/vcpkg/installed/x64-linux/share/seal \
  -DMicrosoft.GSL_DIR=/home/jrj/code/vcpkg/installed/x64-linux/share/Microsoft.GSL \
  -Dzstd_DIR=/home/jrj/code/vcpkg/installed/x64-linux/share/zstd

cmake --build ../build
```

手动流程与脚本完全一致，只是参数显式化，便于在 CI 或容器环境中复用。

## VS Code 集成

- `.vscode/settings.json` 已将 `C_Cpp.default.compileCommands` 指向 `build/compile_commands.json`。
- 若 IntelliSense 报错，可运行 `C/C++: Restart IntelliSense Engine` 或重新生成 `build/`。
- 建议安装 CMake Tools 扩展，以方便切换配置、单击构建/运行。

## 常见问题排查

1. **找不到 vcpkg 或 SEAL**：确认 `VCPKG_ROOT` 路径正确，或在 `configure.sh` 中同步修改。必要时运行 `vcpkg install seal microsoft-gsl zstd` 安装缺失包。
2. **`tc` 相关权限/错误**：网络仿真需要 root；如果只想跑纯计算，可附加 `--profile off` 或直接执行生成的二进制 `build/main`。
3. **OpenMP/AVX 警告**：默认在 CMake 中启用 SSE、关闭 AVX；如果目标机器支持 AVX，可在 `src/CMakeLists.txt` 中开启 `ENABLE_AVX` 加速。
4. **`compile_commands.json` 缺失**：重新运行 `scripts/configure.sh`，脚本会自动开启 `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`。

如需进一步定制 (例如不同 vcpkg triplet、交叉编译或容器化部署)，可以参考 `scripts/configure.sh` 的参数并据此扩展。
