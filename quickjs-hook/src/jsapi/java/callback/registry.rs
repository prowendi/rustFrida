// ============================================================================
// Hook registry
// ============================================================================

/// Hook 类型：统一 Clone+Replace 策略
/// 所有回调统一 JNI 调用约定: x0=JNIEnv*, x1=this/jclass, x2+=args
#[derive(Debug)]
pub(super) enum HookType {
    /// Unified replacement hook (art_router swaps ArtMethod*)
    /// - replacement_addr: heap-allocated replacement ArtMethod (native, jniCode=thunk)
    /// - per_method_hook_target: Some(quickCode) for compiled methods (Layer 3 router hook),
    ///   None for shared stub methods (routed via Layer 1/2)
    Replaced {
        replacement_addr: usize,
        per_method_hook_target: Option<u64>,
    },
}

pub(super) struct JavaHookData {
    pub(super) art_method: u64,
    // Frida-style original method state（unhook 时恢复全部字段）
    pub(super) original_access_flags: u32,
    pub(super) original_entry_point: u64, // quickCode / entry_point_
    pub(super) original_data: u64,        // data_ / jniCode
    // Hook 路径类型
    pub(super) hook_type: HookType,
    // Backup clone for callOriginal (heap, 原始状态副本)
    pub(super) clone_addr: u64,
    // JNI global ref to jclass (for JNI CallNonvirtual/Static calls)
    pub(super) class_global_ref: usize,
    // Return type char from JNI signature: b'V', b'I', b'J', b'Z', b'L', etc.
    pub(super) return_type: u8,
    // Full return type descriptor from signature (e.g. "V", "I", "Ljava/lang/String;", "[B")
    pub(super) return_type_sig: String,
    // JS callback info
    pub(super) ctx: usize,
    pub(super) callback_bytes: [u8; 16],
    pub(super) method_key: String, // "class.method.sig" for lookup
    pub(super) is_static: bool,
    pub(super) param_count: usize,
    // Per-parameter JNI type descriptors (e.g. ["I", "Ljava/lang/String;", "[B"])
    pub(super) param_types: Vec<String>,
    // Hooked class name (dot notation, for wrapping object args)
    #[allow(dead_code)]
    pub(super) class_name: String,
    /// Layer 3 art_router trampoline 地址 (quickCode 原始指令 + jump back)。
    /// callback skip fallback 用它直接调原始方法，避免走 JNI re-entry 路径。
    /// 0 = 无 trampoline（非 compiled 方法，走 Layer 1/2 路由）。
    pub(super) quick_trampoline: u64,
    /// true = thunk 用 BLR (post-callback dispatch), $orig 可设 fast_orig 标志。
    /// false = thunk 用 BR, $orig 必须走 JNI 路径。
    pub(super) use_blr: bool,
}

unsafe impl Send for JavaHookData {}
unsafe impl Sync for JavaHookData {}

/// Global Java hook registry keyed by art_method address
pub(super) static JAVA_HOOK_REGISTRY: Mutex<Option<HashMap<u64, JavaHookData>>> = Mutex::new(None);

/// Java hook 在途计数 —— 只在"JS callback 实际执行中"时 ≠ 0。
///
/// 计数点 (Rust java_hook_callback 进出):
///   enter → IN_FLIGHT += 1   (JSEngine 获取前)
///   drop  → IN_FLIGHT -= 1   (JSEngine 返回后)
///
/// 与旧方案 (汇编 thunk 全局 g_thunk_in_flight) 的区别：
/// - 旧: art_router scan 进入就计, found/not_found 一视同仁, attach 包裹原函数 →
///        任何 Java 阻塞都把 counter 钉死不归零
/// - 新: 只计 "正在执行 JS callback 的线程", 只要 JS 回调链退出就减. 原函数
///        (DoCall 走 not_found 路径) 阻塞不影响计数
///
/// drain=0 语义: "没有任何 JS callback 在执行" → 安全 free callback JSValue /
/// JNI ref / replacement ArtMethod. 栈帧残留于 attach thunk BLR 之后 (callback 未
/// 触发, 线程在原函数内阻塞) 对软清理无影响 (不 munmap pool, 线程后续自然返回).
static IN_FLIGHT_JAVA_HOOK_CALLBACKS: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
static IN_FLIGHT_JAVA_HOOK_CALLBACKS_CV: std::sync::Condvar = std::sync::Condvar::new();

pub(crate) struct InFlightJavaHookGuard;

impl InFlightJavaHookGuard {
    pub(crate) fn enter() -> Self {
        let mut c = IN_FLIGHT_JAVA_HOOK_CALLBACKS.lock().unwrap_or_else(|e| e.into_inner());
        *c += 1;
        Self
    }
}

impl Drop for InFlightJavaHookGuard {
    fn drop(&mut self) {
        let mut c = IN_FLIGHT_JAVA_HOOK_CALLBACKS.lock().unwrap_or_else(|e| e.into_inner());
        *c = c.saturating_sub(1);
        if *c == 0 {
            IN_FLIGHT_JAVA_HOOK_CALLBACKS_CV.notify_all();
        }
    }
}

pub(super) fn in_flight_java_hook_callbacks() -> usize {
    *IN_FLIGHT_JAVA_HOOK_CALLBACKS.lock().unwrap_or_else(|e| e.into_inner())
}

/// 条件变量等 IN_FLIGHT_JAVA_HOOK_CALLBACKS 归零 (callback drop 时 notify_all)
pub(super) fn wait_for_in_flight_java_hook_callbacks(timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    let mut c = IN_FLIGHT_JAVA_HOOK_CALLBACKS.lock().unwrap_or_else(|e| e.into_inner());
    while *c != 0 {
        let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
            return false;
        };
        let (guard, res) = IN_FLIGHT_JAVA_HOOK_CALLBACKS_CV
            .wait_timeout(c, remaining)
            .unwrap_or_else(|e| e.into_inner());
        c = guard;
        if res.timed_out() && *c != 0 {
            return false;
        }
    }
    true
}

/// Parse JNI signature to extract the return type character.
/// "(II)V" → b'V', "(Ljava/lang/String;)Ljava/lang/Object;" → b'L'
pub(super) fn get_return_type_from_sig(sig: &str) -> u8 {
    if let Some(pos) = sig.rfind(')') {
        let ret = &sig[pos + 1..];
        match ret.as_bytes().first() {
            Some(&c) => c,
            None => b'V',
        }
    } else {
        b'V'
    }
}

/// Extract the full return type descriptor from a JNI method signature.
/// "(II)V" → "V", "(I)Ljava/lang/String;" → "Ljava/lang/String;", "()[B" → "[B"
pub(super) fn get_return_type_sig(sig: &str) -> String {
    if let Some(pos) = sig.rfind(')') {
        sig[pos + 1..].to_string()
    } else {
        "V".to_string()
    }
}

pub(super) fn init_java_registry() {
    ensure_registry_initialized(&JAVA_HOOK_REGISTRY);
}

/// Build a unique key string for method lookup
pub(super) fn method_key(class: &str, method: &str, sig: &str) -> String {
    format!("{}.{}{}", class, method, sig)
}
