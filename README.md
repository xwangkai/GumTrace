
# 真机 GumTrace，每 3 秒 1G

基于 Frida Gum (Stalker) 引擎的 ARM64 真机动态指令追踪工具，支持 Android 和 iOS 平台。
## 致谢
-  [Trace UI](https://github.com/imj01y/trace-ui) - 本项目官方指定的 trace 分析工具。高性能 ARM64 执行 trace 可视化分析工具。基于 Tauri 2 + React 构建的桌面应用，专为安全研究员设计，支持千万行或亿行级大规模 trace 的流畅浏览、函数调用树折叠、反向污点追踪、内存/寄存器实时查看等功能。Trace Ul 与 GumTrace 深度适配，是在分析 trace 日志时的得力助手。感谢 [@imj01y](https://github.com/imj01y) 的开源贡献!

## 功能概述

GumTrace 以共享库的形式注入目标进程，对指定模块进行指令级别的动态追踪，并将完整的执行轨迹写入日志文件。

### 核心功能

- **指令级追踪** — 逐条记录 ARM64 指令的执行，包括模块名、绝对地址、相对偏移、助记符和操作数
- **寄存器快照** — 记录每条指令执行时的寄存器读写值（通用寄存器 x0-x28、SIMD 寄存器 q/d/s/h/b、SP、FP、LR、NZCV）
- **内存访问追踪** — 记录内存读写的目标地址（mem_r / mem_w），支持基址 + 索引 + 偏移的复合寻址计算
- **函数调用拦截** — 自动识别 BL/BLR/BR/B 指令的跳转目标，匹配已知符号后打印函数参数和返回值
- **系统调用追踪** — 拦截 SVC 指令，根据系统调用号解析函数名（覆盖 Linux aarch64 全部系统调用）
- **Android JNI 追踪** — 自动识别 JNI 函数调用，解析 jclass、jmethodID、jstring 等 JNI 对象
- **iOS ObjC 追踪** — 拦截 objc_msgSend，解析类名、selector，打印 NSDictionary/NSArray/NSString/NSData/NSNumber 等 ObjC 对象

### 污点分析工具

项目附带一个独立的离线污点分析工具（`src/taint/`），可对 GumTrace 生成的日志进行正向/反向数据流追踪：

- **正向追踪** — 从指定寄存器或内存地址出发，追踪数据如何被传播
- **反向追踪** — 从指定寄存器或内存地址出发，反向追溯数据来源
- 支持寄存器间传播、寄存器与内存间的 load/store 传播、NZCV 标志位传播
- 输出匹配的指令及每步的污点快照

## 日志格式

每行指令记录的格式如下：

```
[模块名] 0x绝对地址!0x相对偏移 助记符 操作数; 寄存器名=值 mem_r=地址 mem_w=地址
```

示例：

```
[libtarget.so] 0x7a3c001890!0x1890 ldr x0, [x1, #0x10]; x1=0x7a3c050000 mem_r=0x7a3c050010
-> x0=0x12345678
call func: strcmp(0x7a3c050010, 0x7a3c060000)
args0: hello
args1: world
ret: 0xffffffffffffffff
```

## 构建

### 环境要求

- CMake >= 3.10
- Android: NDK r29+（arm64-v8a）
- iOS: Xcode + iphoneos SDK（arm64，最低 iOS 12.0）
- Frida Gum 静态库（已包含在 `libs/` 目录）

### 构建 Android

```bash
# 编辑 build_android.sh 中的 ANDROID_NDK_HOME 路径
./build_android.sh
# 产物: build_android/libGumTrace.so
```

### 构建 iOS

```bash
./build_ios.sh
# 产物: build_ios/libGumTrace.dylib
```

### 构建污点分析工具

```bash
cd src/taint
mkdir -p build && cd build
cmake ..
cmake --build .
# 产物: taint_tracker
```

## API

GumTrace 编译为共享库，导出以下 C 接口：

### `init(module_names, trace_file_path, thread_id, options)`

初始化追踪器。

| 参数 | 类型 | 说明 |
|---|---|---|
| `module_names` | `const char*` | 要追踪的模块名，多个用逗号分隔（如 `"libtarget.so,libutils.so"`） |
| `trace_file_path` | `char*` | 日志输出文件路径 |
| `thread_id` | `int` | 要追踪的线程 ID（0 表示追踪当前线程） |
| `options` | `GUM_OPTIONS` | 选项位掩码，`1` 启用 DEBUG 模式（高频刷写日志） |

### `run()`

启动追踪。会创建一个后台线程定期刷写日志文件。

### `set_pause_trace_call(callsite_offset, callee_offset)`

配置一条“进入指定调用时暂停 trace，函数返回后继续”的规则。

| 参数 | 类型 | 说明 |
|---|---|---|
| `callsite_offset` | `uint64_t` | 调用指令在目标模块内的 offset，例如 `BL` 所在地址的模块内偏移 |
| `callee_offset` | `uint64_t` | 被调函数在目标模块内的 offset |

示例：命中 `.text:00000000002A8D34  BL  sub_15B044` 时暂停 `sub_15B044` 函数体内的 trace，并在返回到 `0x2A8D38` 后自动恢复。

### `unrun()`

停止追踪，刷写并关闭日志文件。

## 使用示例（Frida）

通过 Frida 脚本加载 GumTrace 共享库并调用其导出接口，即可对目标进程进行指令追踪。完整示例见 [example.js](example.js)。

### 1. 推送 GumTrace 到设备

```bash
adb push build_android/libGumTrace.so /data/local/tmp/
```

> **注意：** 如果 SO 加载失败（dlopen 返回 NULL），通常是 SELinux 阻止了从 `/data/local/tmp/` 加载共享库。需要先关闭 SELinux：
> ```bash
> adb shell setenforce 0
> ```

### 2. 编写 Frida 脚本

```javascript
// 见 example.js & example_ios.js
```

### 3. 运行

```bash
frida -U -f com.example.app -l hook.js
```

### 4. 拉取日志

```bash
adb pull /data/data/com.example.app/trace.log .
```

## 污点分析工具使用

### 命令行

```bash
# 正向追踪：从第 100 行的 x0 寄存器开始追踪数据流向
./taint_tracker -i trace.log -o result.log -f x0 -l 100

# 反向追踪：从第 500 行的 x0 寄存器反向追溯数据来源
./taint_tracker -i trace.log -o result.log -b x0 -l 500

# 追踪内存地址
./taint_tracker -i trace.log -o result.log -f mem:0x1000 -l 100

# 按相对地址定位起始位置
./taint_tracker -i trace.log -o result.log -f x0 -a 0x1890

# 按字节偏移定位起始位置
./taint_tracker -i trace.log -o result.log -b x0 -p 1048576
```

### 010 Editor 插件

项目提供了 010 Editor 脚本 [TaintTracker.1sc](src/taint/TaintTracker.1sc)，可以在 010 Editor 中直接对 trace 日志进行交互式污点分析。

**安装：**

1. 编辑 `TaintTracker.1sc`，将 `TAINT_TRACKER_PATH` 和 `OUTPUT_DIR` 修改为你本地的路径
2. 在 010 Editor 中通过 **Scripts > Run Script** 加载该脚本，或将其添加到脚本目录中

**使用：**

1. 在 010 Editor 中打开 GumTrace 生成的 trace 日志文件
2. 将光标移到要分析的指令行（以 `[` 开头的行）
3. 运行 `TaintTracker.1sc` 脚本
4. 在弹出的对话框中选择追踪方向（正向/反向）
5. 输入追踪目标（寄存器名如 `x0`，或内存地址如 `mem:0x1000`），脚本会自动提取光标所在行的第一个寄存器作为默认值
6. 脚本自动调用 `taint_tracker` 并在 010 Editor 中打开结果文件

## 项目结构

```
GumTrace/
├── CMakeLists.txt              # 主构建脚本
├── build_android.sh            # Android 构建脚本
├── build_ios.sh                # iOS 构建脚本
├── example.js                  # Frida 使用示例脚本
├── libs/                       # Frida Gum 静态库和头文件
│   ├── FridaGum-Android-17.15.2.h
│   └── FridaGum-IOS-17.15.2.h
└── src/
    ├── main.cpp                # 入口，导出 init/run/unrun 接口
    ├── GumTrace.h/cpp          # 核心追踪引擎（Stalker 回调、指令解析、日志写入）
    ├── CallbackContext.h/cpp   # 指令上下文对象池
    ├── FuncPrinter.h/cpp       # 函数调用参数/返回值打印（含 JNI 和 ObjC）
    ├── Utils.h/cpp             # 工具函数（寄存器值读取、hexdump、字符串格式化）
    ├── platform.h              # 平台检测宏
    └── taint/                  # 离线污点分析工具
        ├── CMakeLists.txt
        ├── main.cpp            # 命令行入口
        ├── TraceParser.h/cpp   # 日志解析器（零分配设计）
        ├── TaintEngine.h/cpp   # 污点传播引擎（正向/反向）
        └── TaintTracker.1sc    # 010 Editor 污点分析脚本
```

## 内置函数识别

GumTrace 内置了对常见库函数参数的自动解析：

| 类别 | 函数 |
|---|---|
| 字符串操作 | `strlen`, `strcmp`, `strncmp`, `strcpy`, `strcat`, `strstr`, `strdup` 等 |
| 内存操作 | `memcpy`, `memmove`, `memset`, `memcmp`, `memmem` 等 |
| 文件操作 | `open`, `openat`, `read`, `write`, `fopen`, `close` 等 |
| 内存分配 | `malloc`, `calloc`, `realloc`, `free` |
| 内存映射 | `mmap`, `mprotect` |
| 动态链接 | `dlopen`, `dlsym`, `dlclose` |
| 格式化 | `sprintf`, `snprintf`, `sscanf` |
| 系统 | `syscall`, `__system_property_get`, `sysconf` |
| JNI (Android) | `FindClass`, `GetMethodID`, `CallObjectMethod`, `GetStringUTFChars` 等全部 JNI 函数 |
| ObjC (iOS) | `objc_msgSend`, `objc_retain`, `objc_release`, `NSClassFromString` 等 |

## 技术细节

- 基于 Frida Gum Stalker 进行代码插桩，使用 `gum_stalker_iterator_put_callout` 在每条指令前插入回调
- 使用 Capstone 反汇编引擎解析 ARM64 指令的操作数和访问类型
- 自动排除系统模块（`/system/`、`/apex/`、`/vendor/` 等路径），仅追踪用户指定的目标模块
- 跳过原子指令（LSE、独占加载/存储）以避免 Stalker 插桩导致的死锁
- 使用 10MB 内存缓冲区减少文件 I/O 次数，提升追踪性能
- 污点分析工具采用零分配解析设计，可高效处理 GB 级日志文件

