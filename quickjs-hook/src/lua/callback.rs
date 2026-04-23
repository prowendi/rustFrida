use super::ffi as lua_ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::java::callback::{
    extract_jni_arg, is_floating_point_type, build_jargs_from_registers,
    invoke_original_jni, InFlightJavaHookGuard, JavaHookCallbackScope,
};

/// 传递给 orig() upvalue 的上下文
#[repr(C)]
pub(crate) struct CallbackContext {
    pub env: crate::jsapi::java::jni_core::JniEnv,
    pub art_method: u64,
    pub class_global_ref: usize,
    pub this_obj: u64,
    pub return_type: u8,
    pub return_type_sig: String,
    pub is_static: bool,
    pub param_count: usize,
    pub param_types: Vec<String>,
    pub jargs_ptr: *const std::ffi::c_void,
    pub quick_trampoline: u64,
}

/// Lua callback 入口 — Frida-style 调用约定:
///   function(self, arg1, arg2, ...)
///   self:orig()          — 原始参数调用
///   self:orig(a1, a2)    — 自定义参数调用
pub unsafe extern "C" fn lua_hook_callback(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let _in_flight = InFlightJavaHookGuard::enter();
    let _scope = JavaHookCallbackScope::enter();

    let art_method_addr = user_data as u64;

    let entry_data = match super::with_lua_hook(art_method_addr, |e| {
        (
            e.bytecode.clone(),
            e.is_raw_bytecode,
            e.is_static,
            e.param_count,
            e.param_types.clone(),
            e.return_type,
            e.return_type_sig.clone(),
            e.class_global_ref,
            e.quick_trampoline,
        )
    }) {
        Some(d) => d,
        None => {
            (*ctx_ptr).x[0] = 0;
            return;
        }
    };

    let (
        bytecode,
        is_raw_bytecode,
        is_static,
        param_count,
        param_types,
        return_type,
        return_type_sig,
        class_global_ref,
        quick_trampoline,
    ) = entry_data;

    let env = (*ctx_ptr).x[0] as crate::jsapi::java::jni_core::JniEnv;
    let hook_ctx = &*ctx_ptr;

    super::api::set_current_env(env as *const std::ffi::c_void);

    let tls = match super::get_thread_lua_state() {
        Some(t) => t,
        None => {
            super::api::clear_current_env();
            fallback_call_original(
                ctx_ptr, env, art_method_addr, class_global_ref,
                param_count, &param_types, return_type, is_static, quick_trampoline,
            );
            return;
        }
    };

    let func_ref = match super::ensure_hook_loaded(tls, art_method_addr, &bytecode, is_raw_bytecode) {
        Ok(r) => r,
        Err(e) => {
            crate::jsapi::console::output_message(&format!("[lua] 加载 callback 失败: {}", e));
            super::api::clear_current_env();
            fallback_call_original(
                ctx_ptr, env, art_method_addr, class_global_ref,
                param_count, &param_types, return_type, is_static, quick_trampoline,
            );
            return;
        }
    };

    let L = tls.state.as_ptr();

    // push callback function
    lua_ffi::lua_rawgeti(L, lua_ffi::LUA_REGISTRYINDEX, func_ref as lua_ffi::lua_Integer);

    // ---- arg1: self table (含 orig 方法) ----
    let jargs = build_jargs_from_registers(hook_ctx, param_count, &param_types);
    let jargs_ptr: *const std::ffi::c_void = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };
    let cb_ctx = CallbackContext {
        env, art_method: art_method_addr, class_global_ref,
        this_obj: hook_ctx.x[1], return_type, return_type_sig,
        is_static, param_count, param_types: param_types.clone(),
        jargs_ptr, quick_trampoline,
    };

    lua_ffi::lua_createtable(L, 0, 2);

    // self.orig = closure(CallbackContext)
    lua_ffi::lua_pushlightuserdata(L, &cb_ctx as *const _ as *mut std::ffi::c_void);
    lua_ffi::lua_pushcclosure(L, Some(super::api::lua_call_original), 1);
    lua_ffi::lua_setfield(L, -2, c"orig".as_ptr());

    // self.__jptr = thisObj (lightuserdata，可传给 jstr 等)
    if !is_static && hook_ctx.x[1] != 0 {
        lua_ffi::lua_pushlightuserdata(L, hook_ctx.x[1] as *mut std::ffi::c_void);
        lua_ffi::lua_setfield(L, -2, c"__jptr".as_ptr());
    }

    // ---- arg2..argN: Java 方法参数，逐个推栈 ----
    let mut gp_index: usize = 0;
    let mut fp_index: usize = 0;
    for i in 0..param_count {
        let type_sig = param_types.get(i).map(|s| s.as_str());
        let (raw, fp_raw) = extract_jni_arg(
            hook_ctx,
            is_floating_point_type(type_sig),
            &mut gp_index,
            &mut fp_index,
        );
        super::api::push_jni_arg(L, raw, fp_raw, type_sig, env as *const std::ffi::c_void);
    }

    // callback(self, arg1, arg2, ...) → 1 返回值
    let nargs = 1 + param_count as i32; // self + params
    let call_ret = lua_ffi::lua_pcall(L, nargs, 1, 0);
    if call_ret != lua_ffi::LUA_OK as i32 {
        let err_s = lua_ffi::lua_tostring_ex(L, -1);
        if !err_s.is_null() {
            let err = std::ffi::CStr::from_ptr(err_s).to_string_lossy();
            crate::jsapi::console::output_message(&format!("[lua] callback error: {}", err));
        }
        lua_ffi::lua_pop(L, 1);
        super::api::clear_current_env();
        fallback_call_original(
            ctx_ptr, env, art_method_addr, class_global_ref,
            param_count, &param_types, return_type, is_static, quick_trampoline,
        );
        return;
    }

    if return_type != b'V' {
        let ret_val = extract_lua_return(L, -1, return_type, env);
        (*ctx_ptr).x[0] = ret_val;
    }
    lua_ffi::lua_pop(L, 1);
    super::api::clear_current_env();
}

/// 提取 Lua 返回值 → JNI u64
/// 支持: nil, boolean, integer, number, string→NewStringUTF, lightuserdata
unsafe fn extract_lua_return(
    L: *mut lua_ffi::lua_State,
    idx: i32,
    return_type: u8,
    env: crate::jsapi::java::jni_core::JniEnv,
) -> u64 {
    match return_type {
        b'V' => 0,
        b'Z' => lua_ffi::lua_toboolean(L, idx) as u64,
        b'B' => lua_ffi::lua_tointeger_ex(L, idx) as i8 as u64,
        b'C' => lua_ffi::lua_tointeger_ex(L, idx) as u16 as u64,
        b'S' => lua_ffi::lua_tointeger_ex(L, idx) as i16 as u64,
        b'I' => lua_ffi::lua_tointeger_ex(L, idx) as i32 as u64,
        b'J' => lua_ffi::lua_tointeger_ex(L, idx) as u64,
        b'F' => (lua_ffi::lua_tonumber_ex(L, idx) as f32).to_bits() as u64,
        b'D' => (lua_ffi::lua_tonumber_ex(L, idx)).to_bits(),
        b'L' | b'[' => {
            if lua_ffi::lua_isnil(L, idx) {
                0
            } else if lua_ffi::lua_type(L, idx) == lua_ffi::LUA_TLIGHTUSERDATA as i32 {
                lua_ffi::lua_touserdata(L, idx) as u64
            } else if lua_ffi::lua_type(L, idx) == lua_ffi::LUA_TSTRING as i32 && !env.is_null() {
                // Lua string → Java String (NewStringUTF)
                super::api::lua_string_to_jstring(L, idx, env)
            } else {
                lua_ffi::lua_tointeger_ex(L, idx) as u64
            }
        }
        _ => lua_ffi::lua_tointeger_ex(L, idx) as u64,
    }
}

unsafe fn fallback_call_original(
    ctx_ptr: *mut hook_ffi::HookContext,
    env: crate::jsapi::java::jni_core::JniEnv,
    art_method_addr: u64,
    class_global_ref: usize,
    param_count: usize,
    param_types: &[String],
    return_type: u8,
    is_static: bool,
    quick_trampoline: u64,
) {
    if env.is_null() {
        (*ctx_ptr).x[0] = 0;
        return;
    }
    let hook_ctx = &*ctx_ptr;
    let jargs = build_jargs_from_registers(hook_ctx, param_count, param_types);
    let jargs_ptr: *const std::ffi::c_void = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };
    let ret = invoke_original_jni(
        env, art_method_addr, class_global_ref,
        hook_ctx.x[1], return_type, is_static, jargs_ptr, quick_trampoline, false,
    );
    if return_type != b'V' {
        (*ctx_ptr).x[0] = ret;
    }
}
