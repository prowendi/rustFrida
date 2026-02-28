//! ART Controller — 全局 ART 内部函数 hook 模块
//!
//! 三层拦截矩阵:
//!
//! Layer 1: 共享 stub 路由 (全局, hook 一次)
//!   hook_install_art_router(quick_generic_jni_trampoline)
//!   hook_install_art_router(quick_to_interpreter_bridge)
//!   hook_install_art_router(quick_resolution_trampoline)
//!
//! Layer 2: Interpreter DoCall (全局, hook 一次)
//!   hook_attach(DoCall[i], on_do_call_enter)
//!
//! Layer 3: 编译方法独立代码路由 (每个被hook的编译方法)
//!   hook_install_art_router(method.quickCode)
//!   在 java_hook_api.rs 中安装
//!
//! 所有路由通过 replacedMethods 映射查找 replacement ArtMethod。

use crate::ffi::hook as hook_ffi;
use crate::jsapi::console::output_message;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use super::art_method::{ArtBridgeFunctions, try_invalidate_jit_cache, read_entry_point};
use super::callback::{get_replacement_method, is_replacement_method};

// ============================================================================
// wxshadow stealth 全局开关
// ============================================================================

/// 全局开关: 是否对 Java hook 的 inline patch 使用 wxshadow stealth 模式。
/// 启用后 C 层 patch_target 优先尝试 wxshadow，失败自动 fallback 到 mprotect。
static STEALTH_ENABLED: AtomicBool = AtomicBool::new(false);

/// 设置 stealth 开关
pub(super) fn set_stealth_enabled(enabled: bool) {
    STEALTH_ENABLED.store(enabled, Ordering::Relaxed);
    output_message(&format!("[wxshadow] stealth 模式: {}", if enabled { "已启用" } else { "已禁用" }));
}

/// 查询 stealth 开关状态
pub(super) fn is_stealth_enabled() -> bool {
    STEALTH_ENABLED.load(Ordering::Relaxed)
}

/// 返回传给 C hook 函数的 stealth 参数值 (0 或 1)
pub(super) fn stealth_flag() -> i32 {
    is_stealth_enabled() as i32
}

// ============================================================================
// ArtController 状态
// ============================================================================

/// 记录已安装的 artController 全局 hook 信息
struct ArtControllerState {
    /// Layer 1: 已 hook 的共享 stub 地址 (jni_trampoline, interpreter_bridge, resolution)
    shared_stub_targets: Vec<u64>,
    /// Layer 2: 已 hook 的 DoCall 函数地址
    do_call_targets: Vec<u64>,
    /// GC 同步 hook 地址 (CopyingPhase, CollectGarbageInternal, RunFlipFunction)
    gc_hook_targets: Vec<u64>,
    /// GetOatQuickMethodHeader hook 地址 (hook_replace, 0 表示未安装)
    oat_header_hook_target: u64,
    /// FixupStaticTrampolines hook 地址 (0 表示未安装)
    fixup_hook_target: u64,
}

unsafe impl Send for ArtControllerState {}
unsafe impl Sync for ArtControllerState {}

/// 全局单例: artController 状态
static ART_CONTROLLER: OnceLock<ArtControllerState> = OnceLock::new();

// ============================================================================
// 初始化
// ============================================================================

/// 惰性初始化 artController: 安装 Layer 1 (共享 stub 路由) + Layer 2 (DoCall hook)。
///
/// 使用 OnceLock 保证只初始化一次。首次调用 Java.hook() 时触发。
///
/// Layer 1: 对 3 个共享 stub 安装 hook_install_art_router，路由 hook 方法到 replacement
/// Layer 2: 对 DoCall 安装 hook_attach，拦截解释器路径
pub(super) fn ensure_art_controller_initialized(bridge: &ArtBridgeFunctions, ep_offset: usize, env: *mut std::ffi::c_void) {
    ART_CONTROLLER.get_or_init(|| {
        output_message("[artController] 开始安装三层拦截矩阵...");

        // B3: 自动清空 JIT 缓存 — 使已内联被 hook 方法的 JIT 代码失效
        unsafe { try_invalidate_jit_cache(); }

        let mut shared_stub_targets = Vec::new();
        let mut do_call_targets = Vec::new();

        // --- Layer 1: 共享 stub 路由 hook ---
        let stubs = [
            ("quick_generic_jni_trampoline", bridge.quick_generic_jni_trampoline),
            ("quick_to_interpreter_bridge", bridge.quick_to_interpreter_bridge),
            ("quick_resolution_trampoline", bridge.quick_resolution_trampoline),
        ];

        for (name, addr) in &stubs {
            if *addr == 0 {
                output_message(&format!("[artController] Layer 1: {} 地址为0，跳过", name));
                continue;
            }
            let trampoline = unsafe {
                hook_ffi::hook_install_art_router(
                    *addr as *mut std::ffi::c_void,
                    ep_offset as u32,
                    stealth_flag(),
                    env,
                )
            };
            if !trampoline.is_null() {
                shared_stub_targets.push(*addr);
                output_message(&format!(
                    "[artController] Layer 1: {} hook 安装成功: {:#x}, trampoline={:#x}",
                    name, addr, trampoline as u64
                ));
            } else {
                output_message(&format!(
                    "[artController] Layer 1: {} hook 安装失败: {:#x}", name, addr
                ));
            }
        }

        // --- Layer 2: DoCall hook (解释器路径) ---
        for (i, &addr) in bridge.do_call_addrs.iter().enumerate() {
            if addr == 0 {
                continue;
            }
            let ret = unsafe {
                hook_ffi::hook_attach(
                    addr as *mut std::ffi::c_void,
                    Some(on_do_call_enter),
                    None,
                    std::ptr::null_mut(),
                    stealth_flag(),
                )
            };
            if ret == 0 {
                do_call_targets.push(addr);
                output_message(&format!(
                    "[artController] Layer 2: DoCall[{}] hook 安装成功: {:#x}", i, addr
                ));
            } else {
                output_message(&format!(
                    "[artController] Layer 2: DoCall[{}] hook 安装失败: {:#x} (ret={})", i, addr, ret
                ));
            }
        }

        // --- GC 同步 hooks ---
        // GC 可能移动 ArtMethod 的 entry_point / declaring_class_，需要在多个 GC 点同步
        let mut gc_hook_targets = Vec::new();

        // Fix 3: hook CopyingPhase/MarkingPhase on_leave
        if bridge.gc_copying_phase != 0 {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    bridge.gc_copying_phase as *mut std::ffi::c_void,
                    None,
                    Some(on_gc_sync_leave),
                    std::ptr::null_mut(),
                    stealth_flag(),
                )
            };
            if ret == 0 {
                gc_hook_targets.push(bridge.gc_copying_phase);
                output_message(&format!(
                    "[artController] GC CopyingPhase hook 安装成功: {:#x}", bridge.gc_copying_phase
                ));
            } else {
                output_message(&format!(
                    "[artController] GC CopyingPhase hook 安装失败: {:#x} (ret={})",
                    bridge.gc_copying_phase, ret
                ));
            }
        }

        // Fix 3: hook CollectGarbageInternal on_leave (主 GC 入口)
        if bridge.gc_collect_internal != 0 {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    bridge.gc_collect_internal as *mut std::ffi::c_void,
                    None,
                    Some(on_gc_sync_leave),
                    std::ptr::null_mut(),
                    stealth_flag(),
                )
            };
            if ret == 0 {
                gc_hook_targets.push(bridge.gc_collect_internal);
                output_message(&format!(
                    "[artController] GC CollectGarbageInternal hook 安装成功: {:#x}",
                    bridge.gc_collect_internal
                ));
            } else {
                output_message(&format!(
                    "[artController] GC CollectGarbageInternal hook 安装失败: {:#x} (ret={})",
                    bridge.gc_collect_internal, ret
                ));
            }
        }

        // Fix 3: hook RunFlipFunction on_enter (线程翻转期间同步)
        if bridge.run_flip_function != 0 {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    bridge.run_flip_function as *mut std::ffi::c_void,
                    Some(on_gc_sync_enter),
                    None,
                    std::ptr::null_mut(),
                    stealth_flag(),
                )
            };
            if ret == 0 {
                gc_hook_targets.push(bridge.run_flip_function);
                output_message(&format!(
                    "[artController] GC RunFlipFunction hook 安装成功: {:#x}",
                    bridge.run_flip_function
                ));
            } else {
                output_message(&format!(
                    "[artController] GC RunFlipFunction hook 安装失败: {:#x} (ret={})",
                    bridge.run_flip_function, ret
                ));
            }
        }

        // --- Fix 4: hook GetOatQuickMethodHeader (replace mode) ---
        // 对 replacement method 返回 NULL，防止 ART 查找堆分配方法的 OAT 代码头
        let mut oat_header_hook_target: u64 = 0;
        if bridge.get_oat_quick_method_header != 0 {
            let trampoline = unsafe {
                hook_ffi::hook_replace(
                    bridge.get_oat_quick_method_header as *mut std::ffi::c_void,
                    Some(on_get_oat_quick_method_header),
                    std::ptr::null_mut(),
                    stealth_flag(),
                )
            };
            if !trampoline.is_null() {
                oat_header_hook_target = bridge.get_oat_quick_method_header;
                output_message(&format!(
                    "[artController] GetOatQuickMethodHeader hook 安装成功: {:#x}, trampoline={:#x}",
                    bridge.get_oat_quick_method_header, trampoline as u64
                ));
            } else {
                output_message(&format!(
                    "[artController] GetOatQuickMethodHeader hook 安装失败: {:#x}",
                    bridge.get_oat_quick_method_header
                ));
            }
        }

        // --- Fix 5: hook FixupStaticTrampolines on_leave ---
        // 类初始化完成后同步 replacement 方法，防止 quickCode 被更新绕过 hook
        let mut fixup_hook_target: u64 = 0;
        if bridge.fixup_static_trampolines != 0 {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    bridge.fixup_static_trampolines as *mut std::ffi::c_void,
                    None,
                    Some(on_gc_sync_leave),
                    std::ptr::null_mut(),
                    stealth_flag(),
                )
            };
            if ret == 0 {
                fixup_hook_target = bridge.fixup_static_trampolines;
                output_message(&format!(
                    "[artController] FixupStaticTrampolines hook 安装成功: {:#x}",
                    bridge.fixup_static_trampolines
                ));
            } else {
                output_message(&format!(
                    "[artController] FixupStaticTrampolines hook 安装失败: {:#x} (ret={})",
                    bridge.fixup_static_trampolines, ret
                ));
            }
        }

        output_message(&format!(
            "[artController] 初始化完成: Layer1={}, Layer2={}, GC={}, OatHeader={}, Fixup={}",
            shared_stub_targets.len(),
            do_call_targets.len(),
            gc_hook_targets.len(),
            if oat_header_hook_target != 0 { "active" } else { "none" },
            if fixup_hook_target != 0 { "active" } else { "none" },
        ));

        ArtControllerState {
            shared_stub_targets,
            do_call_targets,
            gc_hook_targets,
            oat_header_hook_target,
            fixup_hook_target,
        }
    });
}

// ============================================================================
// 回调函数
// ============================================================================

/// DoCall on_enter: 检查 x0 (ArtMethod*) 是否在 replacedMethods 中，有则替换
unsafe extern "C" fn on_do_call_enter(
    ctx_ptr: *mut hook_ffi::HookContext,
    _user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *ctx_ptr;
    let method = ctx.x[0];
    if let Some(replacement) = get_replacement_method(method) {
        ctx.x[0] = replacement;
    }
}

/// GC / FixupStaticTrampolines on_leave 回调: 调用同步函数
unsafe extern "C" fn on_gc_sync_leave(
    _ctx_ptr: *mut hook_ffi::HookContext,
    _user_data: *mut std::ffi::c_void,
) {
    synchronize_replacement_methods();
}

/// RunFlipFunction on_enter 回调: 线程翻转期间同步
unsafe extern "C" fn on_gc_sync_enter(
    _ctx_ptr: *mut hook_ffi::HookContext,
    _user_data: *mut std::ffi::c_void,
) {
    synchronize_replacement_methods();
}

/// Fix 4: GetOatQuickMethodHeader replace-mode 回调
///
/// 对 replacement ArtMethod 返回 NULL，防止 ART 查找堆分配方法的 OAT 代码头。
/// 对其他方法调用原始实现。
unsafe extern "C" fn on_get_oat_quick_method_header(
    ctx_ptr: *mut hook_ffi::HookContext,
    _user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *ctx_ptr;
    let method = ctx.x[0]; // ArtMethod* this

    if is_replacement_method(method) {
        // replacement method → return NULL
        ctx.x[0] = 0;
    } else {
        // 非 replacement → 调用原始实现
        let trampoline = ctx.trampoline;
        if !trampoline.is_null() {
            let result = hook_ffi::hook_invoke_trampoline(ctx_ptr, trampoline);
            (*ctx_ptr).x[0] = result;
        }
    }
}

// ============================================================================
// Fix 6: synchronize_replacement_methods — 统一同步函数
// ============================================================================

/// 同步所有被 hook 方法的关键字段。
///
/// 在多个 ART 内部事件（GC、类初始化等）后调用，确保 hook 仍然生效。
///
/// 同步内容:
/// 1. declaring_class_ 同步: original → replacement (Fix 1)
/// 2. accessFlags 修复: kAccCompileDontBother + clear kAccFastInterpreterToInterpreterInvoke
/// 3. entry_point 验证与恢复 (Fix 2 + existing)
unsafe fn synchronize_replacement_methods() {
    use super::art_method::ART_BRIDGE_FUNCTIONS;
    use super::callback::{JAVA_HOOK_REGISTRY, HookType};
    use super::jni_core::{ART_METHOD_ACCESS_FLAGS_OFFSET, K_ACC_COMPILE_DONT_BOTHER,
                          K_ACC_FAST_INTERP_TO_INTERP, ENTRY_POINT_OFFSET};

    let guard = match JAVA_HOOK_REGISTRY.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let registry = match guard.as_ref() {
        Some(r) => r,
        None => return,
    };

    let ep_offset = match ENTRY_POINT_OFFSET.get() {
        Some(&o) => o,
        None => return,
    };

    // 获取 nterp 和 interpreter_bridge 地址 (共享 stub 方法的 GC 同步用)
    let (nterp, interp_bridge) = match ART_BRIDGE_FUNCTIONS.get() {
        Some(b) => (b.nterp_entry_point, b.quick_to_interpreter_bridge),
        None => (0, 0),
    };

    for (_, data) in registry.iter() {
        let art_method = data.art_method as usize;

        // --- Fix 1: declaring_class_ 同步 ---
        // 移动 GC 会更新原始 ArtMethod 的 declaring_class_ (offset 0, 4 bytes GcRoot)，
        // 但堆分配的 replacement 不会被 GC 追踪。同步以防悬空引用。
        let HookType::Replaced { replacement_addr, .. } = &data.hook_type;
        {
            let declaring_class = std::ptr::read_volatile(art_method as *const u32);
            std::ptr::write_volatile(*replacement_addr as *mut u32, declaring_class);
        }

        // --- flags 修复: 确保 kAccCompileDontBother 在 + kAccFastInterpreterToInterpreterInvoke 不在 ---
        let flags = std::ptr::read_volatile(
            (art_method + ART_METHOD_ACCESS_FLAGS_OFFSET) as *const u32,
        );
        let need_fix = (flags & K_ACC_COMPILE_DONT_BOTHER) == 0
            || (flags & K_ACC_FAST_INTERP_TO_INTERP) != 0;
        if need_fix {
            let fixed = (flags | K_ACC_COMPILE_DONT_BOTHER) & !K_ACC_FAST_INTERP_TO_INTERP;
            std::ptr::write_volatile(
                (art_method + ART_METHOD_ACCESS_FLAGS_OFFSET) as *mut u32,
                fixed,
            );
        }

        // --- Fix 2 + existing: entry_point 验证与恢复 ---
        match &data.hook_type {
            HookType::Replaced { per_method_hook_target: None, .. } => {
                // 共享 stub 方法: 如果 GC 重置 entry_point 为 nterp，再降级为 interpreter_bridge
                if nterp != 0 && interp_bridge != 0 {
                    let current_ep = read_entry_point(data.art_method, ep_offset);
                    if current_ep == nterp {
                        std::ptr::write_volatile(
                            (art_method + ep_offset) as *mut u64,
                            interp_bridge,
                        );
                        hook_ffi::hook_flush_cache(
                            (art_method + ep_offset) as *mut std::ffi::c_void,
                            8,
                        );
                    }
                }
            }
            HookType::Replaced { per_method_hook_target: Some(_), .. } => {
                // 编译方法: entry_point 应为 original_entry_point (已被 inline hook 修改)
                let current_ep = read_entry_point(data.art_method, ep_offset);
                if current_ep != data.original_entry_point {
                    // GC/类初始化 重置了 entry_point (可能变为 nterp)，恢复到被 patch 的原始地址
                    std::ptr::write_volatile(
                        (art_method + ep_offset) as *mut u64,
                        data.original_entry_point,
                    );
                    hook_ffi::hook_flush_cache(
                        (art_method + ep_offset) as *mut std::ffi::c_void,
                        8,
                    );
                }
            }
        }
    }
}

// ============================================================================
// 清理
// ============================================================================

/// 清理所有 artController 全局 hook
///
/// 移除 Layer 1 (共享 stub 路由 hook) 和 Layer 2 (DoCall hook)。
/// 调用路径: cleanup_java_hooks() → cleanup_art_controller()
pub(super) fn cleanup_art_controller() {
    let state = match ART_CONTROLLER.get() {
        Some(s) => s,
        None => return, // 从未初始化，无需清理
    };

    output_message("[artController] 开始清理全局 ART hook...");

    // 移除 Layer 1: 共享 stub 路由 hooks
    for &addr in &state.shared_stub_targets {
        unsafe {
            hook_ffi::hook_remove(addr as *mut std::ffi::c_void);
        }
        output_message(&format!("[artController] Layer 1 hook 已移除: {:#x}", addr));
    }

    // 移除 Layer 2: DoCall hooks
    for &addr in &state.do_call_targets {
        unsafe {
            hook_ffi::hook_remove(addr as *mut std::ffi::c_void);
        }
        output_message(&format!("[artController] Layer 2 DoCall hook 已移除: {:#x}", addr));
    }

    // 移除 GC 同步 hooks
    for &addr in &state.gc_hook_targets {
        unsafe {
            hook_ffi::hook_remove(addr as *mut std::ffi::c_void);
        }
        output_message(&format!("[artController] GC hook 已移除: {:#x}", addr));
    }

    // 移除 GetOatQuickMethodHeader hook
    if state.oat_header_hook_target != 0 {
        unsafe {
            hook_ffi::hook_remove(state.oat_header_hook_target as *mut std::ffi::c_void);
        }
        output_message(&format!(
            "[artController] GetOatQuickMethodHeader hook 已移除: {:#x}",
            state.oat_header_hook_target
        ));
    }

    // 移除 FixupStaticTrampolines hook
    if state.fixup_hook_target != 0 {
        unsafe {
            hook_ffi::hook_remove(state.fixup_hook_target as *mut std::ffi::c_void);
        }
        output_message(&format!(
            "[artController] FixupStaticTrampolines hook 已移除: {:#x}",
            state.fixup_hook_target
        ));
    }

    output_message("[artController] 全局 ART hook 清理完成");
}
