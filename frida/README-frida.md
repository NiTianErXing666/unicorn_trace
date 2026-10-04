# Frida 集成（unitrace_helper.js）

用 Frida 把 unitrace 引擎注入目标 app：hook 指定 JNI/native 函数，命中时
在 unicorn 里仿真执行（syscall 转发真实内核），GumTrace 格式的指令级
trace 自动落盘。

```
frida attach ──> 加载 libtesttrace.so ──> ut_init + trace 文件
     │
     └─ hook 目标函数(replace) ──命中──> revert hook ──> invokeCall 仿真
                                            │              │
                                        重新挂 hook    trace 自动追加到日志
```

## 部署

```bash
# 1. 构建（或从 APK lib/arm64-v8a/ 提取两个库）
./gradlew :app:assembleDebug
LIB=app/build/intermediates/merged_native_libs/debug/mergeDebugNativeLibs/out/lib/arm64-v8a

# 2. push 到设备（root）
adb push $LIB/libtesttrace.so $LIB/libc++_shared.so /data/local/tmp/

# 3. 关键：Android 10+ SELinux 禁止 app 从 /data/local/tmp 加载 so，
#    root 身份把库复制到目标 app 数据目录
adb root
adb shell "cp /data/local/tmp/libtesttrace.so /data/local/tmp/libc++_shared.so /data/data/<目标包名>/ && chmod 644 /data/data/<目标包名>/*.so"
```

修改脚本 `CONFIG`：

```js
traceLibraryPath: "/data/data/<目标包名>/libtesttrace.so",
cxxSharedPath:    "/data/data/<目标包名>/libc++_shared.so",
traceFile: "",                     // 留空 = 自动写到 /data/data/<pkg>/unitrace.log
targets: [{
    moduleName: "libxxx.so",
    hooks: [{
        type: "symbol",            // 或 "offset" + offset: 0x45078
        symbolName: "Java_com_xxx_nativeMethod",
        signature: ["pointer", "pointer", "pointer"],   // JNIEnv*, jobject, args...
        mode: "replace",           // 或 "replay"
        name: "nativeMethod"
    }]
}]
```

## 运行

```bash
# attach 模式（推荐；spawn 在部分魔改 frida-server 上会注错进程）
adb shell am start -n <目标包名>/.MainActivity
frida -D <设备id> -p $(adb shell pidof <目标包名>) -l frida/unitrace_helper.js

# trace 日志（每次命中自动追加）：
adb shell cat /data/data/<目标包名>/unitrace.log
```

## 两种 hook 模式

| 模式 | 行为 | 副作用 |
|---|---|---|
| `replace`（默认） | 真实函数**不执行**，由 `invokeCall` 仿真执行并顶替返回值；函数在 trace 级别 3 下完整记录 | syscall 转发真实内核——副作用发生**一次** |
| `replay` | 真实函数先执行，返回后延时重放一遍用于记录 trace | 副作用发生**两次**，只适合纯计算函数 |

关键机制：frida hook 会改写目标函数头部的指令，引擎按真实内存镜像代码
时会把 frida trampoline 一起仿真进去。脚本在每次 `invokeCall` 前后自动
`Interceptor.revert` / 重新 replace 目标函数，保证引擎读到原始指令。

## trace 输出（自动追加，带 run 头）

```
==== run #1 fn=0x6e26b36800 [libtesttarget.so!tt_add+0x0] insns=2 blocks=1 syscalls=0 ====
[libtesttarget.so] 0x6e26b36800!0x1800 add x0, x1, x0; x1=0x1f
-> x0=0x2a
```

## 脚本内 API（frida REPL 可用）

```js
UnitraceHelper.setTraceLevel(3)                    // 0..3
UnitraceHelper.setTraceFile("/data/data/.../x.log")
UnitraceHelper.info()                              // 引擎状态
UnitraceHelper.traceFunction("libxxx.so", 0x1234, [ptr(1), ptr(2)])  // 手动调用
```

## 已知限制

- **库位置**：引擎 so 必须放在目标 app 数据目录（`app_data_file` 上下文
  才能可执行映射）；`/data/local/tmp` 会被 SELinux 拒绝。目标 app 自带
  的 `libc++_shared.so` 在 classloader namespace 里不可见，脚本会从
  指定路径再加载一份到 default namespace
- **JNI 回调**：目标函数若重度回调 ART（FindClass/NewString 等），仿真
  会连带执行 libart 代码——能跑但慢且未经充分验证；纯计算/JNI 参数读取
  类函数（绝大多数加密/签名函数）无此问题
- **阻塞**：仿真比真机慢 20~60x，命中时目标线程会停顿这么久
- **spawn 模式**：部分魔改 frida-server（如以宿主 app 服务运行的）spawn
  注入会跑错进程，用 attach 模式
- 多线程目标函数（pthread 短路）不支持（clone 拒绝，返回 -EPERM）

## 真机验证

Pixel 5 (Android 13) + frida 16.5.9：attach `com.example.testtrace`，
hook `libtesttarget.so!tt_add`（replace 模式）+ selfTest——
仿真返回 `0x2a`（=42 ✓），`unitrace.log` 自动写入完整 run
（`libtesttarget.so!tt_add+0x0`，2 条指令，写回 `-> x0=0x2a`）。
