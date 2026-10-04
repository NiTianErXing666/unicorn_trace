/**
 * unitrace Frida Helper — libtesttrace.so (unicorn arm64 tracer) 集成脚本
 * https://github.com/NiTianErXing666/unicorn_trace
 *
 * 功能：
 *   1. dlopen 加载 libtesttrace.so（需要先加载 libc++_shared.so）
 *   2. 初始化引擎：ut_init + trace 级别 + ut_set_trace_file（每次
 *      invokeCall 自动把该 run 的完整 trace 追加进日志文件）
 *   3. 等待目标 so 加载（hook android_dlopen_ext），按 offset/symbol
 *      hook 目标 JNI/native 函数
 *   4. 命中时把参数交给 invokeCall 在 unicorn 里执行并记录，
 *      trace 自动落盘
 *
 * 与 QBDI 版 trace_helper.js 的关键差异：
 *   invokeCall 会"代替"真实执行——目标函数在仿真器里跑，其系统调用被
 *   转发到真实内核（副作用真实发生一次）。因此：
 *     - replace 模式（默认推荐）：真实函数不再执行，由仿真结果顶替返回
 *     - replay 模式：真实函数先执行，返回后再重放一遍用于记录 trace
 *       （注意：副作用会执行两次，仅适合观察纯计算函数）
 */

// ==================== 配置区域 ====================

var CONFIG = {
    // 引擎库路径。注意 Android 10+ 的 SELinux 禁止 app 从 /data/local/tmp
    // 加载 so——把两个库放到目标 app 的数据目录（root: adb root 后
    // cp /data/local/tmp/lib*.so /data/data/<pkg>/），这里填对应路径
    traceLibraryPath: "/data/data/com.example.testtrace/libtesttrace.so",
    // libtesttrace.so 依赖 libc++_shared.so，一并放置；进程里已有则跳过
    cxxSharedPath: "/data/data/com.example.testtrace/libc++_shared.so",

    // trace 日志文件：每次 invokeCall 自动追加一段带 run 头的完整 trace。
    // 留空则自动使用目标 app 的 files 目录（app 进程对 /data/local/tmp
    // 没有写权限，日志必须落在 app 自己的可写路径）
    traceFile: "",

    // trace 级别：0 关 1 系统调用 2 +基本块 3 指令级(GumTrace 格式)
    traceLevel: 3,

    // BL 调用观测（独立于 traceLevel）：只记录 bl/blr 调用与返回，
    // 参数/返回值是可打印字符串时自动内联显示——观测开销远低于级别 3
    callTrace: false,

    // 配置完成后自动调用一次首个 hook 目标（验证整条链路），不需要设 false
    selfTest: false,

    // 打印每个 android_dlopen_ext 调用（排查模块加载问题）
    debugDlopen: false,

    // 目标配置
    targets: [
        {
            // 目标 so 模块名（等待其加载后再 hook）
            moduleName: "libtesttarget.so",

            hooks: [
                {
                    // 方式 1: 导出符号名
                    type: "symbol",
                    symbolName: "tt_strdup_upper",

                    // 参数类型（生成 NativeCallback 签名用）
                    signature: ["pointer", "pointer"],

                    // "replace": 仿真执行并顶替返回值（推荐，副作用只发生一次）
                    // "replay":  真实执行后重放记录（副作用会发生两次）
                    mode: "replace",

                    name: "tt_strdup_upper"
                },
                // 方式 2: 模块内偏移
                // {
                //     type: "offset",
                //     offset: 0x45078,
                //     signature: ["pointer", "pointer", "pointer"],
                //     mode: "replace",
                //     name: "encode_function"
                // }
            ]
        }
    ]
};

// ==================== 引擎加载与初始化 ====================

var UnitraceEngine = (function () {
    var loaded = false;
    var fn = {};   // NativeFunction 表

    /**
     * 加载 so。优先 Module.load（frida 自带 linker，用匿名可执行内存映射，
     * 不受 Android 10+ 对 /data/local/tmp 等路径的 exec SELinux 限制），
     * 失败再退回系统 dlopen（so 位于可执行路径时，如 app 自己的 lib 目录）。
     */
    function dlopenSo(path, name) {
        try {
            Module.load(path);
            console.log("[+] Module.load ok: " + name);
            return ptr(1);
        } catch (e) {
            console.log("[*] Module.load failed (" + e.message + "), trying dlopen");
        }
        var dlopenPtr = Module.findExportByName(null, "dlopen");
        if (!dlopenPtr) throw new Error("dlopen not found");
        var dlopen = new NativeFunction(dlopenPtr, "pointer", ["pointer", "int"]);
        var h = dlopen(Memory.allocUtf8String(path), 2);
        if (h.isNull()) {
            var dlerr = Module.findExportByName(null, "dlerror");
            if (dlerr) {
                var e = new NativeFunction(dlerr, "pointer", []);
                var msg = e();
                if (!msg.isNull()) console.log("[-] dlerror: " + msg.readCString());
            }
            return null;
        }
        return h;
    }

    function resolve(sym, ret, args) {
        var addr = Module.findExportByName("libtesttrace.so", sym);
        if (!addr) throw new Error("export not found: " + sym);
        return new NativeFunction(addr, ret, args);
    }

    function ensureLoaded() {
        if (loaded) return true;
        try {
            // libc++_shared.so 必须先行，且总是加载自己这份：app 自带的
            // libc++_shared 位于其 classloader-namespace，我们引擎在
            // default namespace 里的 DT_NEEDED 解析看不到它
            var h = dlopenSo(CONFIG.cxxSharedPath, "libc++_shared.so");
            if (!h) console.log("[!] libc++_shared.so not loaded (continuing)");
            if (!dlopenSo(CONFIG.traceLibraryPath, "libtesttrace.so"))
                throw new Error("failed to load " + CONFIG.traceLibraryPath);
            console.log("[+] libtesttrace.so loaded");

            fn.ut_init          = resolve("ut_init", "int", []);
            fn.invokeCall       = resolve("invokeCall", "pointer",
                                          ["pointer", "pointer", "int"]);
            fn.ut_free_result   = resolve("ut_free_result", "void", ["pointer"]);
            fn.ut_set_level     = resolve("ut_set_trace_level", "void", ["int"]);
            fn.ut_set_trace_file= resolve("ut_set_trace_file", "int", ["pointer"]);
            fn.ut_last_error    = resolve("ut_last_error", "pointer", []);
            fn.ut_engine_info   = resolve("ut_engine_info", "pointer", []);
            fn.ut_set_call_trace = resolve("ut_set_call_trace", "void", ["int"]);
            fn.ut_last_stats    = resolve("ut_last_stats", "pointer", []);

            var rc = fn.ut_init();
            if (rc !== 0) throw new Error("ut_init failed: " + lastError());
            fn.ut_set_level(CONFIG.traceLevel);
            if (CONFIG.callTrace) fn.ut_set_call_trace(1);
            if (CONFIG.traceFile) {
                // 显式路径立即生效
                setupTraceFile(CONFIG.traceFile);
            }
            // 未显式指定：延迟到进程 specialize 之后再自动解析
            // （spawn 门控阶段 /proc/self/cmdline 还不是目标进程）

            console.log("[+] engine: " + fn.ut_engine_info().readCString());
            loaded = true;
            return true;
        } catch (e) {
            console.log("[-] engine load error: " + e.message);
            return false;
        }
    }

    function lastError() {
        try { return fn.ut_last_error().readCString(); } catch (e) { return "?"; }
    }

    var traceFileReady = false;

    function setupTraceFile(path) {
        if (traceFileReady || !loaded) return;
        if (fn.ut_set_trace_file(Memory.allocUtf8String(path)) !== 0) {
            console.log("[-] ut_set_trace_file failed: " + path);
            return;
        }
        traceFileReady = true;
        console.log("[+] trace log -> " + path);
    }

    /** 目标 app 数据目录（trace 日志的默认落点）：从 /proc/self/cmdline 取
     * 包名。必须在进程 specialize 之后调用——spawn 门控阶段读到的是
     * frida-server 宿主进程的 cmdline */
    function setupTraceFileAuto() {
        if (traceFileReady) return;
        try {
            var f = new File("/proc/self/cmdline", "r");
            var line = f.readLine();
            f.close();
            var pkg = line ? line.split("\0")[0].split(":")[0].trim() : null;
            if (!pkg || pkg.indexOf(".") < 0)
                throw new Error("unexpected cmdline: " + pkg);
            setupTraceFile("/data/data/" + pkg + "/unitrace.log");
        } catch (e) {
            console.log("[-] auto trace path failed: " + e.message +
                        " (set CONFIG.traceFile manually)");
        }
    }

    /**
     * 在引擎里执行 targetFn(args...)，返回仿真的 x0。
     * args: NativePointer 数组（JNI 函数的 JNIEnv 指针与 jobject 原样透传）。
     *
     * 重要：frida 的 hook 会把目标函数头部改写成 trampoline，引擎按真实
     * 内存镜像代码时会把这个 trampoline 也仿真进去。因此调用期间必须
     * revert 掉目标函数上的 hook，调用结束后再重新挂上。
     */
    var rehookQueue = [];

    function runInvoke(targetFn, args) {
        var n = args.length;
        var buf = Memory.alloc(8 * 8);
        for (var i = 0; i < 8; i++)
            buf.add(i * 8).writeU64(i < n ? args[i].toUInt64 ? args[i] : uint64(args[i].toString()) : uint64(0));

        // 摘掉目标函数上的 frida hook（若有）
        var hooked = hookedTargets[targetFn.toString()];
        if (hooked) {
            try { Interceptor.revert(targetFn); } catch (e) {}
        }
        var ret;
        try {
            ret = fn.invokeCall(ptr(targetFn), buf, n);
        } finally {
            if (hooked) {
                try { Interceptor.replace(targetFn, hooked); } catch (e) {}
            }
        }
        if (ret.isNull()) {
            console.log("[-] invokeCall failed: " + lastError());
            return null;
        }
        var x0 = ret.readU64();
        fn.ut_free_result(ret);
        return x0;
    }

    /** addr -> NativeCallback（重挂用） */
    var hookedTargets = {};

    return {
        ensureLoaded: ensureLoaded,
        runInvoke: runInvoke,
        lastError: lastError,
        setupTraceFileAuto: setupTraceFileAuto,
        registerHook: function (addr, cb) { hookedTargets[addr.toString()] = cb; },
        unregisterHook: function (addr) { delete hookedTargets[addr.toString()]; },
        info: function () { return loaded ? fn.ut_engine_info().readCString() : "not loaded"; },
        setLevel: function (lv) { if (loaded) fn.ut_set_level(lv); },
        setCallTrace: function (on) { if (loaded) fn.ut_set_call_trace(on ? 1 : 0); },
        setTraceFile: function (path) {
            if (loaded)
                return fn.ut_set_trace_file(Memory.allocUtf8String(path));
            return -1;
        }
    };
})();

// ==================== 参数处理 ====================

var ArgumentProcessor = {
    /** 把 Interceptor 的 InvocationArguments 转成 NativePointer 数组 */
    toArray: function (args, count) {
        var out = [];
        for (var i = 0; i < count; i++) out.push(args[i]);
        return out;
    },

    /** 调试用途：按简单 JNI 惯例预览前几个参数（jstring 转 C 串等由引擎 trace 自行完成） */
    preview: function (args, count) {
        var parts = [];
        for (var i = 0; i < count && i < 4; i++)
            parts.push("0x" + args[i].toString(16));
        return parts.join(", ");
    }
};

// ==================== 模块加载监听 ====================

var ModuleWatcher = (function () {
    var pending = {};
    var installed = false;

    function notify(moduleName) {
        var cbs = pending[moduleName];
        if (!cbs) return;
        var m = Process.findModuleByName(moduleName);
        if (m) {
            delete pending[moduleName];
            cbs.forEach(function (cb) { cb(m); });
        }
    }

    function install() {
        if (installed) return;
        var addr = Module.findExportByName(null, "android_dlopen_ext");
        if (!addr) { console.log("[-] android_dlopen_ext not found"); return; }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var path = args[0].readCString();
                if (!path) return;
                if (CONFIG.debugDlopen) console.log("[dlopen] " + path);
                // 模块以路径最后一段命名
                var name = path.split("/").pop();
                if (pending[name]) {
                    setTimeout(function () { notify(name); }, 10);
                }
            }
        });
        installed = true;
        // 轮询兜底：有些加载路径不走 android_dlopen_ext（如 linkernamespaces
        // 差异、模块已被 linker 预加载），每 2s 扫一次已加载模块
        setInterval(function () {
            Object.keys(pending).forEach(function (name) {
                if (Process.findModuleByName(name)) notify(name);
            });
        }, 2000);
    }

    return {
        waitFor: function (moduleName, cb) {
            install();
            var m = Process.findModuleByName(moduleName);
            if (m) { cb(m); return; }
            console.log("[*] waiting for module: " + moduleName);
            (pending[moduleName] = pending[moduleName] || []).push(cb);
        }
    };
})();

// ==================== Hook 管理 ====================

var HookManager = {
    hookTarget: function (target) {
        ModuleWatcher.waitFor(target.moduleName, function (module) {
            console.log("[+] module loaded: " + target.moduleName + " @ " + module.base);
            UnitraceEngine.setupTraceFileAuto();   // 进程已 specialize

            target.hooks.forEach(function (hook) {
                try {
                    var addr;
                    if (hook.type === "offset") {
                        addr = module.base.add(hook.offset);
                    } else if (hook.type === "symbol") {
                        addr = Module.findExportByName(target.moduleName, hook.symbolName);
                        if (!addr) throw new Error("symbol not found: " + hook.symbolName);
                    } else {
                        throw new Error("unknown hook type: " + hook.type);
                    }

                    var mode = hook.mode || "replace";
                    var sig = hook.signature || [];
                    var argCount = Math.min(sig.length, 8);   // x0..x7

                    if (mode === "replace") {
                        // 仿真执行并顶替返回值：真实函数不再执行
                        var cb = new NativeCallback(function () {
                            var a = ArgumentProcessor.toArray(arguments, argCount);
                            console.log("[*] " + hook.name + " hit (" +
                                        ArgumentProcessor.preview(a, argCount) + ") -> emulated");
                            var x0 = UnitraceEngine.runInvoke(addr, a);
                            console.log("[+] " + hook.name + " emulated ret: 0x" +
                                        (x0 === null ? "?" : x0.toString(16)));
                            return x0 === null ? ptr(0) : ptr(x0.toString());
                        }, "pointer", sig);

                        Interceptor.replace(addr, cb);
                        UnitraceEngine.registerHook(addr, cb);
                        console.log("[+] replaced " + hook.name + " @ " + addr);
                    } else {
                        // replay：真实执行，返回后重放记录（副作用 x2，慎用）
                        Interceptor.attach(addr, {
                            onEnter: function (args) {
                                this.a = ArgumentProcessor.toArray(args, argCount);
                                this.fn = addr;
                            },
                            onLeave: function (retval) {
                                var a = this.a, target = this.fn;
                                console.log("[*] " + hook.name + " real ret=0x" +
                                            retval.toString(16) + ", replaying for trace");
                                setTimeout(function () {
                                    UnitraceEngine.runInvoke(target, a);
                                }, 0);
                                return retval;
                            }
                        });
                        console.log("[+] attached(replay) " + hook.name + " @ " + addr);
                    }
                } catch (e) {
                    console.log("[-] hook setup failed (" + hook.name + "): " + e.message);
                }
            });
        });
    },

    applyConfig: function (config) {
        config.targets.forEach(function (t) { HookManager.hookTarget(t); });
    }
};

// ==================== 自检 ====================

function selfTest() {
    var t = CONFIG.targets[0];
    var h = t.hooks[0];
    ModuleWatcher.waitFor(t.moduleName, function (module) {
        var addr = h.type === "symbol"
            ? Module.findExportByName(t.moduleName, h.symbolName)
            : module.base.add(h.offset);
        console.log("[*] selfTest invoking " + (h.name || addr) + " @ " + addr);
        // 两个无害参数（示例函数 tt_add(11,31)）
        var args = [ptr(11), ptr(31)];
        var x0 = UnitraceEngine.runInvoke(addr, args);
        console.log("[+] selfTest ret: 0x" + (x0 === null ? "?" : x0.toString(16)));
    });
}

// ==================== 主入口 ====================

function main() {
    console.log("========================================");
    console.log(" unitrace Frida Helper");
    console.log("========================================");

    if (!UnitraceEngine.ensureLoaded()) {
        console.log("[-] engine unavailable, aborting");
        return;
    }
    HookManager.applyConfig(CONFIG);
    if (CONFIG.selfTest) selfTest();
    console.log("[*] hooks armed, waiting for hits");
}

setImmediate(main);

// 脚本内可编程接口（attach 后可在 REPL 调用）
globalThis.UnitraceHelper = {
    setTraceLevel: function (lv) { UnitraceEngine.setLevel(lv); },
    setTraceFile: function (p) { UnitraceEngine.setTraceFile(p); },
    info: function () { console.log(UnitraceEngine.info()); },
    /** 手动对任意地址发起一次 trace 调用 */
    traceFunction: function (moduleName, offsetOrSymbol, args) {
        var m = Process.findModuleByName(moduleName);
        if (!m) { console.log("[-] module not loaded: " + moduleName); return; }
        var addr = (typeof offsetOrSymbol === "number")
            ? m.base.add(offsetOrSymbol)
            : Module.findExportByName(moduleName, offsetOrSymbol);
        return UnitraceEngine.runInvoke(addr, args || []);
    }
};
