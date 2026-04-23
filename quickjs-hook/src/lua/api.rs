use super::ffi;
use super::state::LuaState;

pub(crate) unsafe fn register_lua_apis(state: &LuaState) {
    state.register_fn("print", Some(lua_print));
}

/// lua_upvalueindex 在 C 中是宏，Rust 这边手动实现
#[inline]
pub(crate) fn lua_upvalueindex(i: i32) -> i32 {
    ffi::LUA_REGISTRYINDEX - i
}

/// Lua print() → console callback
unsafe extern "C" fn lua_print(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let n = ffi::lua_gettop(L);
    let mut parts = Vec::with_capacity(n as usize);
    for i in 1..=n {
        let s = ffi::lua_tostring_ex(L, i);
        if !s.is_null() {
            parts.push(std::ffi::CStr::from_ptr(s).to_string_lossy().into_owned());
        } else {
            let tp = ffi::lua_type(L, i);
            match tp as u32 {
                ffi::LUA_TNIL => parts.push("nil".to_string()),
                ffi::LUA_TBOOLEAN => {
                    let b = ffi::lua_toboolean(L, i);
                    parts.push(if b != 0 { "true" } else { "false" }.to_string());
                }
                ffi::LUA_TNUMBER => {
                    let n = ffi::lua_tonumber_ex(L, i);
                    parts.push(format!("{}", n));
                }
                _ => parts.push(format!("<{}>", lua_typename_str(tp))),
            }
        }
    }
    let msg = parts.join("\t");
    crate::jsapi::console::output_message(&msg);
    0
}

unsafe fn lua_typename_str(tp: i32) -> &'static str {
    match tp as u32 {
        ffi::LUA_TNIL => "nil",
        ffi::LUA_TBOOLEAN => "boolean",
        ffi::LUA_TNUMBER => "number",
        ffi::LUA_TSTRING => "string",
        ffi::LUA_TTABLE => "table",
        ffi::LUA_TFUNCTION => "function",
        ffi::LUA_TUSERDATA => "userdata",
        ffi::LUA_TLIGHTUSERDATA => "lightuserdata",
        ffi::LUA_TTHREAD => "thread",
        _ => "unknown",
    }
}

/// ctx:orig() — 通过 JNI 调用原始方法
/// upvalue 1 = lightuserdata (CallbackContext*)
pub(crate) unsafe extern "C" fn lua_call_original(
    L: *mut ffi::lua_State,
) -> std::os::raw::c_int {
    let ctx_ptr = ffi::lua_touserdata(L, lua_upvalueindex(1));
    if ctx_ptr.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }
    let cb_ctx = &*(ctx_ptr as *const super::callback::CallbackContext);

    let ret = crate::jsapi::java::callback::invoke_original_jni(
        cb_ctx.env,
        cb_ctx.art_method,
        cb_ctx.class_global_ref,
        cb_ctx.this_obj,
        cb_ctx.return_type,
        cb_ctx.is_static,
        cb_ctx.jargs_ptr,
        cb_ctx.quick_trampoline,
        false,
    );

    push_return_value(L, ret, cb_ctx.return_type);
    1
}

unsafe fn push_return_value(
    L: *mut ffi::lua_State,
    raw: u64,
    return_type: u8,
) {
    match return_type {
        b'V' => ffi::lua_pushnil(L),
        b'Z' => ffi::lua_pushboolean(L, if raw != 0 { 1 } else { 0 }),
        b'B' => ffi::lua_pushinteger(L, raw as i8 as ffi::lua_Integer),
        b'C' => {
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            let cs = std::ffi::CString::new(s).unwrap();
            ffi::lua_pushstring(L, cs.as_ptr());
        }
        b'S' => ffi::lua_pushinteger(L, raw as i16 as ffi::lua_Integer),
        b'I' => ffi::lua_pushinteger(L, raw as i32 as ffi::lua_Integer),
        b'J' => ffi::lua_pushinteger(L, raw as ffi::lua_Integer),
        b'F' => ffi::lua_pushnumber(L, f32::from_bits(raw as u32) as ffi::lua_Number),
        b'D' => ffi::lua_pushnumber(L, f64::from_bits(raw) as ffi::lua_Number),
        b'L' | b'[' => {
            if raw == 0 {
                ffi::lua_pushnil(L);
            } else {
                ffi::lua_pushlightuserdata(L, raw as *mut std::ffi::c_void);
            }
        }
        _ => ffi::lua_pushinteger(L, raw as ffi::lua_Integer),
    }
}

/// 将 JNI 参数推入 Lua 栈 (根据类型签名)
/// String 参数通过 JNI 读取为 Lua string，其他对象作为 lightuserdata
pub(crate) unsafe fn push_jni_arg(
    L: *mut ffi::lua_State,
    raw: u64,
    fp_raw: u64,
    type_sig: Option<&str>,
    env: *const std::ffi::c_void,
) {
    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => {
            ffi::lua_pushinteger(L, raw as ffi::lua_Integer);
            return;
        }
    };
    match sig.as_bytes()[0] {
        b'Z' => ffi::lua_pushboolean(L, if raw != 0 { 1 } else { 0 }),
        b'B' => ffi::lua_pushinteger(L, raw as i8 as ffi::lua_Integer),
        b'C' => {
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            let cs = std::ffi::CString::new(s).unwrap();
            ffi::lua_pushstring(L, cs.as_ptr());
        }
        b'S' => ffi::lua_pushinteger(L, raw as i16 as ffi::lua_Integer),
        b'I' => ffi::lua_pushinteger(L, raw as i32 as ffi::lua_Integer),
        b'J' => ffi::lua_pushinteger(L, raw as ffi::lua_Integer),
        b'F' => {
            let f = f32::from_bits(fp_raw as u32);
            ffi::lua_pushnumber(L, f as f64);
        }
        b'D' => {
            let d = f64::from_bits(fp_raw);
            ffi::lua_pushnumber(L, d);
        }
        b'L' | b'[' => {
            if raw == 0 {
                ffi::lua_pushnil(L);
            } else if sig == "Ljava/lang/String;" && !env.is_null() {
                // 通过 JNI vtable 直接读 String
                push_jni_string(L, raw, env);
            } else {
                ffi::lua_pushlightuserdata(L, raw as *mut std::ffi::c_void);
            }
        }
        _ => ffi::lua_pushinteger(L, raw as ffi::lua_Integer),
    }
}

/// 从 JNI String 读取 UTF8 并推入 Lua 栈
unsafe fn push_jni_string(
    L: *mut ffi::lua_State,
    raw: u64,
    env: *const std::ffi::c_void,
) {
    // JNI vtable: GetStringUTFChars = index 169, ReleaseStringUTFChars = index 170
    let vtable = *(env as *const *const usize);
    type GetStringUtfCharsFn = unsafe extern "C" fn(
        *const std::ffi::c_void,
        *mut std::ffi::c_void,
        *mut u8,
    ) -> *const std::os::raw::c_char;
    type ReleaseStringUtfCharsFn = unsafe extern "C" fn(
        *const std::ffi::c_void,
        *mut std::ffi::c_void,
        *const std::os::raw::c_char,
    );
    let get_str: GetStringUtfCharsFn = std::mem::transmute(*vtable.add(169));
    let rel_str: ReleaseStringUtfCharsFn = std::mem::transmute(*vtable.add(170));

    let obj = raw as *mut std::ffi::c_void;
    let chars = get_str(env, obj, std::ptr::null_mut());
    if !chars.is_null() {
        ffi::lua_pushstring(L, chars);
        rel_str(env, obj, chars);
    } else {
        ffi::lua_pushnil(L);
    }
}
