# unicorn_trace — Android arm64 上的 unicorn 系统级 trace 工具

在真实 Android 设备（arm64）上，用 [Unicorn](https://github.com/unicorn-engine/unicorn) 2.1.4 执行**本进程内任意原生函数**：传入地址和参数即可执行并取回返回值。模拟器遇到的一切需求都转接给真实系统处理——内存按需从真实进程镜像、系统调用逐个转发真实内核、信号交给真实的内核投递与原生 handler 执行。

已在 Pixel 5 (Android 13) 真机验证：21/21 自动化测试全部通过（另有 CLI 版 22/22）。

## 核心接口

```c
/* app/src/main/cpp/unitrace/uni_trace.h */
long* invokeCall(void* address, void* args, int args_length);
```

- `address`：本进程内已加载的任意函数地址（如 `dlsym` 拿到的 libc/libtarget 函数）
- `args`：`long` 数组，依次放入 x0..x7（最多 8 个，可为指针）
- 返回：`malloc` 的 `long[]`，`ret[0]` = x0；失败返回 NULL，`ut_last_error()` 给出原因
- 附加：`invokeCallRegs()` 额外回填 x0..x7；`ut_last_trace()` 输出系统调用/基本块轨迹；`ut_set_trace_level(0..3)` 控制trace粒度（1=系统调用，2=+基本块，3=+每条指令）

## 架构

```
Java/Kotlin UI (MainActivity)
        │ JNI
libtesttrace.so ── unitrace 引擎 (uni_trace.cpp) ── unicorn 2.1.4 (aarch64-softmmu, 源码级集成)
        │                                     │
        │  dlsym 取目标函数                    ├─ UC_HOOK_MEM_INVALID  → 懒镜像
        └─ libtesttarget.so (被测函数示例)      ├─ UC_HOOK_INTR         → SVC 转发
                                              ├─ UC_HOOK_MEM_WRITE    → 写回/脏页
                                              └─ UC_HOOK_BLOCK/CODE   → 轨迹
```

### 1. 懒内存镜像（同一虚拟地址）
被测函数的代码、libc、linker、TLS、调用者传入的缓冲区——全部位于真实进程地址空间。guest 首次访问未映射地址时，引擎查 `/proc/self/maps`，把对应页面（带前后余量）以相同地址 RWX 映射进 unicorn 并拷入真实内容。目标代码因此天然能调用 libc 全家（PLT/GOT 懒解析也在 guest 内走通）。

### 2. SVC 系统调用转发（全部转接真实内核）
guest 执行 `svc #0` 时，寄存器参数原样（剥去指针 tag）转发给真实内核 `syscall()`；返回值以**内核原始约定**（`-errno`）写回 x0，guest 侧 bionic 包装层自行转 errno——`tt_errno_test` 验证了这条路径。

- 缓冲区类系统调用（read/write/pread/ioctl 类/stat 族/clock_gettime/getrandom/futex/poll/ppoll/recvmsg/sendmsg/rt_sigaction/…）在转发前后做 unicorn↔真实 内存同步，两个视图保持一致
- mmap/munmap/mprotect 同步维护 unicorn 侧映射
- clone/fork/exec 拒绝（返回 -EPERM）；exit/exit_group 优雅停止并带回退出码
- 未特判的系统调用按原样转发并记录（trace 可见）

### 3. 信号：转接真实系统
- `rt_sigaction/rt_sigprocmask/tgkill/kill/...` 全部转发真实内核；**bionic 与内核的 sigaction 布局差异由引擎翻译**，并自带 sigreturn trampoline
- `tgkill` 发出的信号在**真实线程**上投递，handler 以**原生代码在真实栈上执行**（验证用例：模拟中 `tgkill(SIGUSR2/SIGSEGV)` → 真 handler 跑完 → sigreturn → 模拟无缝继续，返回值带回捕获标志）
- 信号类系统调用返回后全量刷新镜像，handler 对真实内存的写入对 guest 可见
- 模拟内部产生的访存错误（真实进程未映射/PROT_NONE）报告为 emulated SIGSEGV 并停止，附 PC 符号化与 opcode

### 4. 内存一致性（写回）
unicorn 2.1.4 无 WRITE_AFTER 事件，采用两级写回：
- 标量写（≤8 字节）：pre-write 钩子的 `value` 参数**立即直写**真实内存（保持与真实 handler 的时序）
- 宽写（SIMD 16B）：标记脏页，模拟结束统一刷回
- 每次 `invokeCall` 开始时，把 guest 非私有页从真实内存刷新（调用者在两次调用之间改的真实内存对 guest 可见）

**私有化规则**（guest 独占视图，绝不写回，避免污染宿主）：系统库（/apex、/system）数据页、真实 [heap]（宿主引擎自己的 C++ 对象所在）。

### 5. guest 隔离堆 + 分配器跳板
- `brk` 不转发内核：引擎预留 512MB 双映射区（真实进程 mmap 一次 + unicorn 按需镜像，同地址），guest 分配器完全隔离于宿主 malloc——否则 guest 的堆写会摧毁 tracer 自身
- bionic scudo 在 guest 内有一致性隐患（MTE 指针 tag、chunk header 校验），镜像时把指向真实 malloc/calloc/realloc/free 的指针（GOT/函数指针）改写为引擎跳板（`mov x8,#magic; svc; ret`），由引擎在隔离堆上以 bump 方式服务

### 6. CPU 指纹仿真（模拟真实设备的 CPU）
`ut_set_cpu_profile("host")`（默认）让仿真 CPU 的可观测身份与**本机真实 CPU 完全一致**：

| 项 | 来源 / 效果 |
|---|---|
| CTR_EL0 | 宿主 `mrs ctr_el0` 直读 → 运行时覆盖 unicorn 的 CONST 寄存器（`uc_arm64_ut_cpu_id_override` shim） |
| DCZID_EL0 | 宿主 `mrs dczid_el0` 直读 → 覆盖 `dcz_blocksize` |
| MIDR_EL1 | 由 /proc/cpuinfo (implementer/variant/part/revision) 重建 → 写 `cp15.c0_cpuid`（EL1 读在 EL0 本就 UNDEF，与真机一致） |
| SCTLR.UCT/DZE | 置位，EL0 可读 CTR、可 DC ZVA——与生产内核一致（EL0 读 CTR 不再 trap） |
| SVE 门控 | CPACR ZEN=01：EL0 的 SVE 指令（rdvl 等）**按真机无 SVE 行为 trap** |
| NEON/DotProd/LSE/CRC | UC_CPU_ARM64_MAX 全量保留（A76 具备），udot/ldadd 正常执行 |
| /proc/cpuinfo、AT_HWCAP | 系统调用转发+真实进程内存，天然真值 |

真机验证：guest `mrs ctr_el0`=0x84448004 == 宿主；`mrs dczid_el0`=0x4 == 宿主；rdvl 触发 UNDEF（同真机）；udot/ldaddal 正常执行。`ut_set_cpu_profile("off")` 恢复 qemu 原始值。

### 7. 对 unicorn/qemu 的源码级补丁（`app/src/main/cpp/unicorn/qemu/`，搜 "unitrace"）
Android bionic 生态强依赖 MTE/TBI 指针 tag（scudo 返回值带高字节 tag），unicorn/qemu 5.0 原样无法处理：
1. `target/arm/helper.c`：MMU 关闭路径强制 TBI=1（tagged 地址不再触发 AddressSize fault）
2. `target/arm/tlb_helper.c`：`arm_cpu_tlb_fill` 入口剥 tag
3. `accel/tcg/cputlb.c` + `include/exec/cpu-all.h`：`load_helper/store_helper/tlb_hit` 统一剥 tag，使 tagged 访问与未 tag 页面共享 TLB/宿主 RAM

另：CPU model 设为 `UC_CPU_ARM64_MAX`（默认 CPU 无 FEAT_LSE，跑不了 libc 的 CAS/SWP 原子指令）；x18/TPIDR_EL0/TPIDRRO_EL0 取真实线程值（TLS/errno/stack-guard 全部原生可用）。

## 构建 & 运行

```bash
cd testtrace
./gradlew :app:assembleDebug        # 首次编译 unicorn+qemu，数分钟
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.example.testtrace/.MainActivity --ez autotest true
adb logcat -s unitrace:I            # 查看测试报告
```

UI 支持：RUN TESTS 全量自测、INIT 引擎信息、自定义调用（十六进制地址 + 逗号分隔参数）、trace 级别切换。

**CLI 版**（/data/local/tmp 直跑，调试利器）：
```bash
adb push app/build/intermediates/cxx/Debug/*/obj/arm64-v8a/unitrace_cli /data/local/tmp/
adb shell "cd /data/local/tmp && LD_LIBRARY_PATH=. ./unitrace_cli"        # 全量
adb shell "cd /data/local/tmp && UT_TRACE=2 LD_LIBRARY_PATH=. ./unitrace_cli 3"  # 单测+轨迹
```

## 测试覆盖（真机 Pixel 5, Android 13）

| 类别 | 用例 |
|---|---|
| 纯计算 | add / mul / fib(30) |
| libc | strdup_upper(真 malloc+toupper) / sum_malloc(1000) / snprintf / 全局 .data/.bss |
| 系统调用 | getpid / write(2) / clock_gettime+结构体回写 / getrandom / openat+read+close(/proc/self/maps) / errno 语义 |
| 信号 | 不投递 tgkill(sig=0) / SIGUSR2 / SIGSEGV（真实 handler 原生执行后继续模拟） |
| 同步原语 | futex(FUTEX_WAKE+字同步) / pthread_mutex(锁 100 次) |
| 栈 | 递归求和 / 32×4KB 深栈帧 |
| 大内存 | 64KB memcpy + FNV 校验（SIMD 写、脏页刷回、写穿透） |
| CPU 指纹 | CTR_EL0/DCZID_EL0 == 宿主值；SVE trap（同真机）；DotProd/LSE 指令可执行 |
| GumTrace trace | 指令行/写回/mem_r/mem_w/call(PLT 穿透+字符串参数)/ret/svc 七类行 |
| BL 调用观测 | 只记 bl/blr+ret；参数/返回值字符串自动识别（"hi unicorn" 实测）；开销远低于指令级 |
| Tenet 导出 | delta 格式经 IDA 插件解析器语法校验通过，trace 直接导入 IDA 回放 |

## GumTrace 风格指令级 trace（capstone 反汇编）

trace 级别 3 下，引擎输出与 [GumTrace](https://github.com/lidongyooo/GumTrace) 同款格式的指令日志（内嵌 capstone 5.0.6，仅 AArch64）：

```
[unitrace_cli] 0x5c94b92bc8!0x22cbc8 sub sp, sp, #0x40; sp=0x7477821000
-> sp=0x7477820fc0
[unitrace_cli] 0x5c94b92bcc!0x22cbcc stp x29, x30, [sp, #0x30]; fp=0x0 lr=0xc0ffee000000 mem_w=0x7477820ff0 mem_w=0x7477820ff8
[unitrace_cli] 0x5c94b92bd8!0x22cbd8 ldr x8, [sp, #0x18]; sp=0x7477820fc0 mem_r=0x7477820fd8
-> x8=0x5c94e07ea4
call func: libc.so!__strlen_chk+0x0(0x587c617124, 0xffffffffffffffff, 0x0, 0x0)
args0: hi unicorn
ret: 0xa
svc write(0x1, 0x7f..., 0x23) = 0x23
```

- 每条指令：`[模块] 0x绝对!0x相对 助记符 操作数; 源寄存器=值 mem_r/mem_w=地址`
- `-> 寄存器=值`：该指令的写回（在下一条指令边界读取，保证是执行后的值）
- `call func:`：bl/blr 自动**穿透 PLT**（解 adrp/ldr 读 GOT，最多 3 跳）解析到真实符号；前 3 个参数若指向可读 ASCII 字符串自动附加 `argsN:` 行
- `ret:`：返回时打印 x0
- `svc 名(参数) = 返回值`：系统调用行，openat 类附带 `path:` 字符串
- 写回/内存字段采用 pending-line 模型：指令前缀在执行前生成，内存访问在执行中收集，寄存器值在下一条指令钩子时读取——三类信息严格对齐到正确的指令
- 缓冲上限 64MB；两种落盘方式：
  - `ut_trace_to_file(path)`：一次性导出当前缓冲
  - **`ut_set_trace_file(path)`（推荐）**：初始化时传入日志路径，之后**每次 invokeCall 自动追加**一段带 run 头的完整 trace（`==== run #N fn=0x... [模块!符号] insns/blocks/syscalls ====`），失败的 run 也记录部分 trace；传 NULL 关闭
- CLI：`UT_TRACE=3 UT_FILE=/data/local/tmp/t.log ./unitrace_cli`（内部走 ut_set_trace_file，多 run 自动累积）；Java：`nativeSetTraceFile(path)`

## 反时间检测（虚拟时钟）

TCG 仿真比真机慢 20~60 倍，计时检测（读 `cntvct_el0` 前后取差、`clock_gettime` 测循环耗时）一测一个准。对策：**guest 的时间按指令数推进，不按仿真墙钟推进**（`ut_set_time_simulation(1, cpu_hz)` 默认开启）：

| 时间源 | 处理 |
|---|---|
| `MRS CNTVCT_EL0/CNTPCT` | qemu 补丁劫持 `gt_virt_cnt_read`，返回引擎维护的虚拟计数器；每个基本块按指令数累加（IPC≈1 @2.4GHz 可配），19.2MHz 换算 |
| `clock_gettime/gettimeofday` | SVC 转发点直接从虚拟时钟生成 timespec，不读真实时钟 |
| `nanosleep/clock_nanosleep/futex` 等真阻塞 | 阻塞的真实墙钟时长 1:1 折算进虚拟时钟——"睡 50ms 再看表"依然准 |
| `CNTKCTL_EL1` | 置 EL0PCTEN/EL0VCTEN，EL0 可读计数器（与真机内核一致，否则 MRS 直接 trap） |

真机实测对比（同样 100k 次空循环 ≈ 60 万条指令）：

```
宿主真机直跑:  ticks=6150~7317  (~0.011 ticks/insn)
仿真内(虚拟钟): ticks=7680      (~0.013 ticks/insn)   ← 同数量级，无法区分
仿真内(关闭后): 上述值会放大 20~60 倍，一测即穿
```

## BL 调用观测模式（轻量观测）

`ut_set_call_trace(1)`（独立于 trace 级别，Java：`nativeSetCallTrace`，frida：`CONFIG.callTrace`）——只记录函数调用与返回，参数/返回值指向可打印 C 字符串时自动内联显示：

```
call libc.so!__strlen_chk+0x0(0x7a79b04ea4 | 0x59d119a00c "hi unicorn", 0xffffffffffffffff, 0x0, 0x0) from 0x59d0f25aa0
ret  0xa
ret  0x59d119a00c "hi unicorn"
```

实现要点：每个基本块入口用 capstone 扫一次找出 bl/blr/ret 站点（按 pc 缓存），单条全局指令钩子在非调用指令上只做一次哈希查找——观测开销远低于级别 3。PLT 自动穿透解析真实符号。输出走 `ut_last_trace()` 并包含在 `ut_set_trace_file()` 日志里。

## 稳定性与可维护性

- **观测模块独立编译单元**：`ut_internal.h` 定义核心与观测模块间的窄接口（CachedInsn/反汇编/寄存器读取/PLT 穿透/字符串探测），新观测特性落在自己的 .cpp（首例 `ut_calltrace.cpp`），核心不再膨胀
- **镜像失控保护**：单次 run 镜像超过 20000 页即中止并给出明确原因（防野指针无限镜像）
- **缓冲上限告警**：指令 trace（64MB）与调用观测（8MB）触顶一次性提示，不再静默丢弃
- **invokeCall 参数判空**：args 为 NULL 且 args_length>0 直接报错

## 性能优化（热路径缓存一览）

| 热路径 | 频率 | 优化 | 收益 |
|---|---|---|---|
| `hook_block` 虚拟钟推进 | 每基本块 | 2 次 64 位除法 → 预计算倒数定点乘法（2^32 定点，128 位中间量） | 纯计算循环 ~3x |
| `hook_write_mark` 页属性 | 每标量写 | ~2000 项 regions 二分 + sscanf 路径判断 → 页号哈希 O(1)（PG_WRITABLE/PG_PRIVATE/PG_MAPPED），maps 刷新世代懒失效 | 写密集 ~1.2-1.3x |
| 符号解析 | 每个 block/call/PLT | `sym_cache`（unordered_map，同 PC 只 dladdr 一次）+ `follow_plt` 结果缓存（stub 字节不变）+ `dl_iterate_phdr` 一次性模块表二分 | trace 级别显著 |
| sync 缓冲 | 每个缓冲区 syscall | 每次 `vector` 堆分配 → 引擎级复用缓冲 | 消除 malloc 抖动 |
| run-start 镜像刷新 | 每次 invokeCall | 跳过只读页（代码页永不变化）+ 可写页先 memcmp 再写 | 短函数调用固定开销大降 |
| fault hook 已映射页 | 每次同页再 fault | 页号哈希直接 return true（覆盖跨页访问的所有页） | 镜像稳定后近零开销 |

实测（Pixel 5，同一 binary 三轮中位）：`tt_fib(30)` 2663→850us（**3.1x**），`memcpy 64KB` 742→672ms（1.1x，瓶颈已转为 TCG 翻译本身 263K 块），短调用（strdup/snprintf）持平——其耗时主导是首次 libc 路径镜像（一次性）。

注意：页属性缓存对 "MAPPED 但非 WRITABLE" 的页保持保守回退（重查 maps），因为 mprotect 会在映射不变的情况下改变写权限。

## 生态调研与集成（GitHub 安卓 trace 工具）

| 工具 | 方式 | 借鉴/集成点 |
|---|---|---|
| [unidbg](https://github.com/zhkl0228/unidbg) | Java 全系统仿真 | 不集成（手写 syscall/内存伪造不如镜像真实进程）；其生态规模印证了 invokeCall 类 API 的价值 |
| [QBDI](https://github.com/QBDI/QBDI) | 进程内 LLVM JIT 重写 | 已对标：无 syscall/信号拦截层；其 memAccess 回调粒度已由 mem_r/mem_w 覆盖 |
| [GumTrace](https://github.com/lidongyooo/GumTrace) | frida+Stalker 指令 trace | 已集成其日志格式（本项目 level 3 的七类行） |
| [Tenet (IDA 插件)](https://github.com/NiTianErXing666/Tenet-IDA9.2) | delta 格式 trace + IDA 回放 | **已集成导出器**（见下）——trace 直接进 IDA 工作流 |
| frida-trace / r2frida | 函数级快速观测 | 已由 BL 调用观测模式覆盖 |
| AndroidNativeEmu | 教学 | 无新可集成点 |

## Tenet 格式导出（IDA 回放）

`ut_set_tenet_file(path)`——level 3 指令追踪**同时**输出 Tenet delta 格式（每指令一行，可直接被 Tenet-IDA9.2 插件的 file.py 解析器导入回放）：

```
PC=0x5f1851ae00,X29=0x0,X30=0xc0ffee000000,MW=0x7b5fc48ff0:0000000000000000,MW=0x7b5fc48ff8:000000eeffc00000
PC=0x5f1851adfc,SP=0x7b5fc48fd0
```

- 寄存器规范名：X0..X30/SP（fp→X29、lr→X30、w 视图剥前缀）；读寄存器=指令输入（执行前值），写寄存器=执行后值，同寄存器时写值后发（parser 语义即 post-exec）
- `MR/MW=0xaddr:hex` 内存读写载荷（≤16 字节，小端原始字节）
- 每次 `ut_set_tenet_file` 重置文件，后续 run 追加为单一连续流
- 真机验证：68 行 trace 经 Operator 仓库解析器语法校验（ip_lines=68、mem_entries=32、bad=0）

## 已知限制（v1）

- 仅 arm64；单引擎单线程串行调用（互斥锁保护）
- clone/fork/exec 拒绝；模拟内的 SIGSEGV 不构造 sigframe 投递（报告后停止）
- guest 对系统库 .data 的修改是 guest 私有的（有意为之，保护宿主 libc 状态）
- ioctl 等变长参数系统调用按原样转发，不做缓冲区同步
- 浮点参数不走 x0..x7 约定（可后续加 v0..v7 支持）
- 性能为原生的大约 1/20~1/60（TCG 翻译 + 钩子开销），trace 级别越高越慢

## Frida 集成

`frida/unitrace_helper.js`：加载引擎 so、hook 指定 JNI/native 函数、命中
即仿真执行并自动把 trace 追加到日志文件。部署与用法见
[frida/README-frida.md](frida/README-frida.md)（真机 Pixel 5 已端到端验证：
attach → hook tt_add → 仿真返回 42 → unitrace.log 自动记录完整 run）。

## 目录

```
testtrace/app/src/main/cpp/
├── unitrace/uni_trace.{h,cpp}   # 引擎核心（镜像/syscall/信号/虚拟时钟/CPU 指纹）
├── unitrace/ut_internal.h       # 核心↔观测模块的内部接口
├── unitrace/ut_calltrace.cpp    # BL 调用观测（参数/返回值字符串自动识别）
├── testtarget/testtarget.c      # 被测函数库
├── native-lib.cpp               # JNI 桥 + 测试驱动
├── capstone/                    # capstone 5.0.6（仅 AArch64，指令级 trace 用）
├── frida/unitrace_helper.js     # Frida 注入 + hook + trace 落盘脚本
├── frida/README-frida.md        # 部署与用法
├── cli/cli_main.cpp             # 真机 CLI 自测
├── CMakeLists.txt               # unicorn 以 add_subdirectory 集成（仅 aarch64）
└── unicorn/                     # unicorn 2.1.4 源码（含上文 3 处补丁，搜 "unitrace patch"）
```
