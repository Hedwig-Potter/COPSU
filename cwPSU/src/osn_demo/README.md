# OSN Demo 示例

本示例演示如何在独立项目中调用 PSU 仓库提供的 `OSNSender` / `OSNReceiver`，完成一次最小的 Oblivious Shuffle Network（permute + share）流程。

## 目录结构

```
examples/osn_demo/
├── main.cpp      # 示例源代码
└── README.md     # 使用说明
```

`main.cpp` 完整呈现了：
1. 构造本地输入集合；
2. 通过 `Session/Channel` 建立发送方与接收方；
3. 分别初始化 `OSNSender` 与 `OSNReceiver` 并运行 `run_osn`；
4. 将双方 share 进行按位异或，校验置换后的结果。

## 编译与运行

先确保仓库已配置并编译依赖：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target osn_demo -j 6
```

默认示例会以集合大小 \(2^4 = 16\)、单线程、IKNP OT (`ot_type=1`) 运行。你可以在 `build` 目录下执行：

```bash
./osn_demo            # 使用默认参数
./osn_demo 10 2       # 集合元素个数 2^10，使用 2 条通道并行
./osn_demo 10 2 2     # 使用 silent OT，需预先生成缓存
```

若选择 `ot_type=2`（silent OT），程序会在当前目录生成 `osn_demo_cache_*` 前缀的缓存文件；后续运行会自动复用。

## 在独立项目中复用

1. **引入源码**：将 `osn/` 目录以及本示例中的 `main.cpp` 复制到你的项目，并把 `libOTe`/`cryptoTools` 作为依赖加入构建系统。
2. **编译设置**：
   - 启用 `-DENABLE_BOOST` 或在源码顶部定义宏；
   - 在 CMake 中 `add_subdirectory(libOTe)`，然后 `target_link_libraries(<target> osn libOTe cryptoTools)`；
   - 包含路径需指向 `osn/` 与 `libOTe/out/install/<preset>/include`。
3. **调用流程**：
   - 为发送方和接收方各自构建 `IOService`、`Session`、`Channel`；
   - 调用 `OSNSender::init(size, ot_type, cache_prefix)` 与 `OSNReceiver::init(size, ot_type)`；
   - 分别执行 `run_osn` 获取 share；
   - 使用 `sender.dest` 获得随机置换，或直接按元素异或还原。

更多细节可参考 `osn_demo/main.cpp` 中的完整实现。