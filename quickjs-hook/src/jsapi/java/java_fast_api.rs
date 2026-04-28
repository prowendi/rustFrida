//! Java.fastMethod() backend used by fast callbacks.
//!
//! This is intentionally fast-only: registration rejects methods that do not
//! currently have an independent quick-code entrypoint. Slow/reflection/JNI
//! calls stay in the JS callback path.

use crate::ffi;
use crate::jsapi::callback_util::{
    extract_string_arg, js_u64_to_js_number_or_bigint, set_js_u64_property, throw_internal_error, throw_type_error,
};
use crate::jsapi::console::output_verbose;
use crate::value::JSValue;
use std::cell::Cell;
use std::ffi::CString;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use super::art_method::*;
use super::callback::{get_return_type_from_sig, parse_jni_param_types};
use super::jni_core::*;
use super::reflect::{decode_field_id, decode_method_id, find_class_safe};
use super::safe_mem::{refresh_mem_regions, safe_read_u32};

#[derive(Clone, Debug)]
pub(crate) struct FastMethod {
    pub(crate) art_method: u64,
    #[allow(dead_code)]
    class_global_ref: u64,
    class_mirror: u64,
    pub(crate) is_static: bool,
    pub(crate) param_types: Vec<String>,
    shorty: CString,
}

#[derive(Clone, Debug)]
pub(crate) struct FastConstructor {
    #[allow(dead_code)]
    pub(crate) class_global_ref: u64,
    pub(crate) class_mirror: u64,
    pub(crate) art_method: u64,
    pub(crate) param_types: Vec<String>,
    shorty: CString,
}

#[derive(Clone, Debug)]
pub(crate) struct FastField {
    #[allow(dead_code)]
    pub(crate) art_field: u64,
    pub(crate) offset: u32,
    pub(crate) is_static: bool,
    pub(crate) value_type: u8,
    #[allow(dead_code)]
    pub(crate) jni_sig: String,
    #[allow(dead_code)]
    pub(crate) class_name: String,
    #[allow(dead_code)]
    pub(crate) field_name: String,
}

static FAST_METHODS: OnceLock<Mutex<Vec<FastMethod>>> = OnceLock::new();
static FAST_CONSTRUCTORS: OnceLock<Mutex<Vec<FastConstructor>>> = OnceLock::new();
static FAST_FIELDS: OnceLock<Mutex<Vec<FastField>>> = OnceLock::new();
static FAST_ART_EXCEPTION_SEEN: AtomicU64 = AtomicU64::new(0);
static FAST_ART_EXCEPTION_CLEARED: AtomicU64 = AtomicU64::new(0);
static FAST_ART_HANDLE_SCOPE_ENTER: AtomicU64 = AtomicU64::new(0);
static FAST_ART_HANDLE_SCOPE_UNAVAILABLE: AtomicU64 = AtomicU64::new(0);
static FAST_ART_HANDLE_SCOPE_LEAKED: AtomicU64 = AtomicU64::new(0);
static FAST_ART_HANDLE_SCOPE_MAX_ROOTS: AtomicU64 = AtomicU64::new(0);
static FAST_ART_HANDLE_SCOPE_ROOT_FAILED: AtomicU64 = AtomicU64::new(0);
static FAST_ART_HANDLE_SCOPE_CAPACITY_EXCEEDED: AtomicU64 = AtomicU64::new(0);
static QUICK_ENTRYPOINTS_OFFSET: AtomicUsize = AtomicUsize::new(0);
static FAST_TLAB_ALLOC_HIT: AtomicU64 = AtomicU64::new(0);
static FAST_TLAB_ALLOC_MISS: AtomicU64 = AtomicU64::new(0);
static FAST_QUICK_ALLOC_SLOW_PATH: AtomicU64 = AtomicU64::new(0);
static ART_CALLEE_SAVE_SUSPEND_METHOD: OnceLock<u64> = OnceLock::new();
static ART_QUICK_TEST_SUSPEND_ENTRYPOINT: OnceLock<u64> = OnceLock::new();

const QUICK_ENTRYPOINTS_OFFSET_FAILED: usize = usize::MAX;
const QUICK_ENTRYPOINT_COUNT: usize = 174;
const QUICK_ALLOC_OBJECT_INITIALIZED_INDEX: usize = 6;
const QUICK_TEST_SUSPEND_INDEX: usize = 105;
const QUICK_JNI_METHOD_START_INDEX: usize = 45;
const QUICK_JNI_METHOD_END_INDEX: usize = 46;
const QUICK_SCAN_LIMIT: usize = 16384;
const QUICK_MIN_LIBART_POINTERS: usize = 40;
const THREAD_CARD_TABLE_OFFSET: usize = 0x90;
const THREAD_EXCEPTION_OFFSET: usize = THREAD_CARD_TABLE_OFFSET + std::mem::size_of::<usize>();
const THREAD_LOCAL_POS_OFFSET: usize = THREAD_CARD_TABLE_OFFSET + 26 * std::mem::size_of::<usize>();
const THREAD_LOCAL_END_OFFSET: usize = THREAD_LOCAL_POS_OFFSET + std::mem::size_of::<usize>();
const MIRROR_OBJECT_CLASS_OFFSET: usize = 0;
const MIRROR_OBJECT_LOCK_WORD_OFFSET: usize = 4;
const MAX_TLAB_FAST_OBJECT_SIZE: u32 = 1 << 20;
const FAST_ART_HANDLE_SCOPE_CAPACITY: usize = 256;
const FAST_ART_STACK_INVOKE_WORDS: usize = 64;

#[repr(C)]
struct FastArtHandleScope {
    link: u64,
    capacity: i32,
    size: u32,
    refs: [u32; FAST_ART_HANDLE_SCOPE_CAPACITY],
}

impl FastArtHandleScope {
    fn new(link: u64) -> Self {
        Self {
            link,
            capacity: FAST_ART_HANDLE_SCOPE_CAPACITY as i32,
            size: 0,
            refs: [0; FAST_ART_HANDLE_SCOPE_CAPACITY],
        }
    }
}

#[inline]
fn update_fast_max(target: &AtomicU64, value: u64) {
    let mut observed = target.load(Ordering::Acquire);
    while value > observed {
        match target.compare_exchange(observed, value, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(v) => observed = v,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct FastArtRoot {
    slot: u32,
}

thread_local! {
    static CURRENT_FAST_ART_HANDLE_SCOPE: Cell<*mut FastArtHandleScope> = const { Cell::new(std::ptr::null_mut()) };
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RequestedCompileKind {
    Auto,
    Fast,
    Baseline,
    Optimized,
}

impl RequestedCompileKind {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "fast" => Some(Self::Fast),
            "baseline" => Some(Self::Baseline),
            "optimized" | "opt" => Some(Self::Optimized),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Fast => "fast",
            Self::Baseline => "baseline",
            Self::Optimized => "optimized",
        }
    }

    fn sequence(self) -> &'static [u32] {
        match self {
            // Mirrors ART's JitAtFirstUse behavior: fast first, then baseline.
            Self::Auto => &[1, 2, 3],
            Self::Fast => &[1],
            Self::Baseline => &[2],
            Self::Optimized => &[3],
        }
    }
}

pub(crate) struct CompileResult {
    pub(crate) before: u64,
    pub(crate) after: u64,
    pub(crate) success: bool,
    pub(crate) compiled: bool,
    pub(crate) kind: &'static str,
    pub(crate) message: String,
}

#[no_mangle]
pub unsafe extern "C" fn art_quick_callee_save_suspend_method() -> *mut std::ffi::c_void {
    *ART_CALLEE_SAVE_SUSPEND_METHOD.get_or_init(|| unsafe { resolve_callee_save_suspend_method().unwrap_or(0) })
        as *mut std::ffi::c_void
}

#[no_mangle]
pub unsafe extern "C" fn art_quick_test_suspend_entrypoint() -> *mut std::ffi::c_void {
    *ART_QUICK_TEST_SUSPEND_ENTRYPOINT.get_or_init(|| unsafe {
        let env = get_thread_env().unwrap_or(std::ptr::null_mut());
        current_art_thread(env)
            .and_then(|thread| quick_entrypoint(thread as usize, QUICK_TEST_SUSPEND_INDEX))
            .unwrap_or(0)
    }) as *mut std::ffi::c_void
}

#[no_mangle]
pub unsafe extern "C" fn art_quick_top_quick_frame_offset() -> u64 {
    super::art_controller::cached_thread_top_quick_frame_offset()
        .map(|v| v as u64)
        .unwrap_or(u64::MAX)
}

unsafe fn resolve_callee_save_suspend_method() -> Option<u64> {
    const CALLEE_SAVE_EVERYTHING_FOR_SUSPEND_CHECK: u32 = 5;
    let runtime = resolve_art_runtime_instance()?;

    type GetCalleeSaveMethodFn = unsafe extern "C" fn(*mut std::ffi::c_void, u32) -> *mut std::ffi::c_void;
    for sym_name in [
        "_ZN3art7Runtime19GetCalleeSaveMethodENS_14CalleeSaveTypeE",
        "_ZN3art7Runtime28GetCalleeSaveMethodUncheckedENS_14CalleeSaveTypeE",
    ] {
        let sym = crate::jsapi::module::libart_dlsym(sym_name);
        if sym.is_null() {
            continue;
        }
        let get_method: GetCalleeSaveMethodFn = std::mem::transmute(sym);
        let method = get_method(runtime, CALLEE_SAVE_EVERYTHING_FOR_SUSPEND_CHECK);
        if !method.is_null() {
            crate::jsapi::console::output_message(&format!(
                "[fast] ART callee-save suspend method via {}: {:?}",
                sym_name, method
            ));
            return Some(method as u64);
        }
    }

    if let Some(method) = resolve_callee_save_suspend_method_from_quick_stub(runtime) {
        return Some(method);
    }

    crate::jsapi::console::output_message("[fast] ART callee-save suspend method unavailable");
    None
}

unsafe fn resolve_callee_save_suspend_method_from_quick_stub(runtime: *mut std::ffi::c_void) -> Option<u64> {
    let mut entry = crate::jsapi::module::libart_dlsym("art_quick_test_suspend") as u64;
    if entry == 0 {
        let env = get_thread_env().unwrap_or(std::ptr::null_mut());
        entry =
            current_art_thread(env).and_then(|thread| quick_entrypoint(thread as usize, QUICK_TEST_SUSPEND_INDEX))?;
    }

    let runtime_addr = runtime as u64;
    for i in 0..192usize {
        let insn = std::ptr::read_unaligned((entry as usize + i * 4) as *const u32);
        if (insn & 0xffc0_0000) != 0xf940_0000 {
            continue;
        }
        let rt = insn & 0x1f;
        let rn = (insn >> 5) & 0x1f;
        if rt != rn {
            continue;
        }
        let offset = (((insn >> 10) & 0xfff) as u64) * 8;
        if offset < 5 * 8 || offset > 0x8000 {
            continue;
        }
        let method = std::ptr::read_volatile((runtime_addr + offset) as *const u64) & 0x00ff_ffff_ffff_ffff;
        if method == 0 || !looks_like_callee_save_method_array(runtime_addr, offset) {
            continue;
        }
        crate::jsapi::console::output_message(&format!(
            "[fast] ART callee-save suspend method from art_quick_test_suspend: method={:#x}, runtime_off=0x{:x}, stub={:#x}",
            method, offset, entry
        ));
        return Some(method);
    }
    None
}

unsafe fn looks_like_callee_save_method_array(runtime: u64, suspend_method_offset: u64) -> bool {
    let first = runtime + suspend_method_offset - 5 * 8;
    let mut previous = 0u64;
    for i in 0..6u64 {
        let method = std::ptr::read_volatile((first + i * 8) as *const u64) & 0x00ff_ffff_ffff_ffff;
        if method == 0 || (method & 0x3) != 0 {
            return false;
        }
        if previous != 0 && method == previous {
            return false;
        }
        previous = method;
    }
    true
}

unsafe fn resolve_art_runtime_instance() -> Option<*mut std::ffi::c_void> {
    let instance_ptr = crate::jsapi::module::libart_dlsym("_ZN3art7Runtime9instance_E");
    if !instance_ptr.is_null() {
        let raw = std::ptr::read_volatile(instance_ptr as *const u64) & 0x00ff_ffff_ffff_ffff;
        if raw != 0 {
            return Some(raw as *mut std::ffi::c_void);
        }
    }

    let current_sym = crate::jsapi::module::libart_dlsym("_ZN3art7Runtime7CurrentEv");
    if !current_sym.is_null() {
        let current: unsafe extern "C" fn() -> *mut std::ffi::c_void = std::mem::transmute(current_sym);
        let runtime = current();
        if !runtime.is_null() {
            return Some(runtime);
        }
    }

    crate::jsapi::console::output_message("[fast] ART Runtime::instance_ unavailable");
    None
}

fn fast_methods() -> &'static Mutex<Vec<FastMethod>> {
    FAST_METHODS.get_or_init(|| Mutex::new(Vec::new()))
}

fn fast_constructors() -> &'static Mutex<Vec<FastConstructor>> {
    FAST_CONSTRUCTORS.get_or_init(|| Mutex::new(Vec::new()))
}

fn fast_fields() -> &'static Mutex<Vec<FastField>> {
    FAST_FIELDS.get_or_init(|| Mutex::new(Vec::new()))
}

fn make_shorty(sig: &str) -> CString {
    let return_sig = sig
        .rsplit_once(')')
        .map(|(_, ret)| ret)
        .filter(|ret| !ret.is_empty())
        .unwrap_or("V");
    let mut shorty = Vec::with_capacity(sig.len() + 1);
    shorty.push(shorty_char(return_sig));
    for param in parse_jni_param_types(sig) {
        shorty.push(shorty_char(param.as_str()));
    }
    CString::new(shorty).unwrap_or_else(|_| CString::new("V").unwrap())
}

fn shorty_char(type_sig: &str) -> u8 {
    match type_sig.as_bytes().first().copied().unwrap_or(b'V') {
        b'L' | b'[' => b'L',
        ch => ch,
    }
}

unsafe fn resolve_fast_method(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    signature: &str,
    force_static: bool,
) -> Result<(u64, u64, u64, bool), String> {
    let c_method = CString::new(method_name).map_err(|_| "invalid method name")?;
    let c_sig = CString::new(signature).map_err(|_| "invalid signature")?;
    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        jni_check_exc(env);
        return Err(format!("FindClass('{}') failed", class_name));
    }

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let class_global = new_global_ref(env, cls);
    if class_global.is_null() || jni_check_exc(env) {
        delete_local_ref(env, cls);
        return Err(format!("NewGlobalRef failed for {}", class_name));
    }

    if !force_static {
        let get_method_id: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
        let method_id = get_method_id(env, cls, c_method.as_ptr(), c_sig.as_ptr());
        if !method_id.is_null() && !jni_check_exc(env) {
            let art_method = decode_method_id(env, cls, method_id as u64, false);
            delete_local_ref(env, cls);
            return Ok((art_method, method_id as u64, class_global as u64, false));
        }
        jni_check_exc(env);
    }

    let get_static_method_id: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
    let method_id = get_static_method_id(env, cls, c_method.as_ptr(), c_sig.as_ptr());
    if !method_id.is_null() && !jni_check_exc(env) {
        let art_method = decode_method_id(env, cls, method_id as u64, true);
        delete_local_ref(env, cls);
        return Ok((art_method, method_id as u64, class_global as u64, true));
    }
    jni_check_exc(env);
    delete_local_ref(env, cls);
    delete_global_ref(env, class_global);

    Err(format!("method not found: {}.{}{}", class_name, method_name, signature))
}

pub(crate) fn get_fast_method(handle: u64) -> Option<FastMethod> {
    if handle == 0 {
        return None;
    }
    let methods = fast_methods().lock().unwrap_or_else(|e| e.into_inner());
    methods.get((handle - 1) as usize).cloned()
}

pub(crate) fn get_fast_constructor(handle: u64) -> Option<FastConstructor> {
    if handle == 0 {
        return None;
    }
    let constructors = fast_constructors().lock().unwrap_or_else(|e| e.into_inner());
    constructors.get((handle - 1) as usize).cloned()
}

pub(crate) fn get_fast_field(handle: u64) -> Option<FastField> {
    if handle == 0 {
        return None;
    }
    let fields = fast_fields().lock().unwrap_or_else(|e| e.into_inner());
    fields.get((handle - 1) as usize).cloned()
}

unsafe fn is_fast_field_type(sig: &str) -> bool {
    matches!(
        sig.as_bytes().first().copied(),
        Some(b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' | b'L' | b'[')
    )
}

unsafe fn parse_fast_options(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    opt_index: i32,
) -> Result<(bool, RequestedCompileKind), ffi::JSValue> {
    if argc <= opt_index {
        return Ok((false, RequestedCompileKind::Auto));
    }
    let opt = JSValue(*argv.add(opt_index as usize));
    if opt.is_bool() {
        return Ok((opt.to_bool().unwrap_or(false), RequestedCompileKind::Auto));
    }
    if opt.is_string() {
        let Some(kind_s) = opt.to_string(ctx) else {
            return Ok((false, RequestedCompileKind::Auto));
        };
        let Some(kind) = RequestedCompileKind::from_str(kind_s.as_str()) else {
            return Err(throw_type_error(ctx, b"invalid compile kind\0"));
        };
        return Ok((true, kind));
    }
    if opt.is_object() {
        let compile_val = opt.get_property(ctx, "compile");
        let should_compile = compile_val.to_bool().unwrap_or(false);
        compile_val.free(ctx);

        let kind_val = opt.get_property(ctx, "kind");
        let kind = if kind_val.is_string() {
            let kind_s = kind_val.to_string(ctx).unwrap_or_else(|| "auto".to_string());
            let Some(kind) = RequestedCompileKind::from_str(kind_s.as_str()) else {
                kind_val.free(ctx);
                return Err(throw_type_error(ctx, b"invalid compile kind\0"));
            };
            kind
        } else {
            RequestedCompileKind::Auto
        };
        kind_val.free(ctx);
        return Ok((should_compile, kind));
    }
    Ok((false, RequestedCompileKind::Auto))
}

pub(crate) unsafe extern "C" fn js_java_fast_method(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return throw_type_error(
            ctx,
            b"fastMethod(class, method, sig[, options]) requires at least 3 arguments\0",
        );
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let method_name = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_str = match extract_string_arg(ctx, JSValue(*argv.add(2)), b"arg 2 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str, false)
    };

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let (art_method, _method_id, class_global_ref, is_static) =
        match resolve_fast_method(env, &class_name, &method_name, &actual_sig, force_static) {
            Ok(v) => v,
            Err(msg) => return throw_internal_error(ctx, msg),
        };

    let (should_compile, compile_kind) = match parse_fast_options(ctx, argc, argv, 3) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let spec = get_art_method_spec(env, art_method);
    let bridge = find_art_bridge_functions(env, spec.entry_point_offset);
    let mut entry_point = read_entry_point(art_method, spec.entry_point_offset);
    if is_art_quick_entrypoint(entry_point, &bridge) && should_compile {
        let compile = compile_art_method_to_quick(env, art_method, spec.entry_point_offset, bridge, compile_kind);
        entry_point = compile.after;
        crate::jsapi::console::output_verbose(&format!(
            "[fastMethod] compile {}.{}{} kind={} success={} before={:#x} after={:#x} msg={}",
            class_name,
            method_name,
            actual_sig,
            compile.kind,
            compile.success,
            compile.before,
            compile.after,
            compile.message
        ));
    }
    if is_art_quick_entrypoint(entry_point, &bridge) {
        return throw_internal_error(
            ctx,
            format!(
                "fastMethod rejected {}.{}{}: no independent quick entrypoint (entry={:#x})",
                class_name, method_name, actual_sig, entry_point
            ),
        );
    }

    let method = FastMethod {
        art_method,
        class_global_ref,
        class_mirror: super::decode_global_jobject_raw(env, class_global_ref as *mut std::ffi::c_void).unwrap_or(0),
        is_static,
        param_types: parse_jni_param_types(&actual_sig),
        shorty: make_shorty(&actual_sig),
    };
    let mut methods = fast_methods().lock().unwrap_or_else(|e| e.into_inner());
    methods.push(method);
    js_u64_to_js_number_or_bigint(ctx, methods.len() as u64)
}

pub(crate) unsafe extern "C" fn js_java_fast_constructor(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return throw_type_error(
            ctx,
            b"fastConstructor(class, sig[, options]) requires at least 2 arguments\0",
        );
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_str = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    if get_return_type_from_sig(&sig_str) != b'V' {
        return throw_type_error(ctx, b"constructor signature must return void\0");
    }

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let (art_method, _method_id, class_global_ref, is_static) =
        match resolve_fast_method(env, &class_name, "<init>", &sig_str, false) {
            Ok(v) => v,
            Err(msg) => return throw_internal_error(ctx, msg),
        };
    if is_static {
        return throw_internal_error(
            ctx,
            format!("constructor resolved as static: {}{}", class_name, sig_str),
        );
    }

    let (should_compile, compile_kind) = match parse_fast_options(ctx, argc, argv, 2) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let spec = get_art_method_spec(env, art_method);
    let bridge = find_art_bridge_functions(env, spec.entry_point_offset);
    let mut entry_point = read_entry_point(art_method, spec.entry_point_offset);
    if is_art_quick_entrypoint(entry_point, &bridge) && should_compile {
        let compile = compile_art_method_to_quick(env, art_method, spec.entry_point_offset, bridge, compile_kind);
        entry_point = compile.after;
        crate::jsapi::console::output_verbose(&format!(
            "[fastConstructor] compile {}.<init>{} kind={} success={} before={:#x} after={:#x} msg={}",
            class_name, sig_str, compile.kind, compile.success, compile.before, compile.after, compile.message
        ));
    }
    if is_art_quick_entrypoint(entry_point, &bridge) {
        return throw_internal_error(
            ctx,
            format!(
                "fastConstructor rejected {}.<init>{}: no independent quick entrypoint (entry={:#x})",
                class_name, sig_str, entry_point
            ),
        );
    }

    let class_mirror = super::decode_global_jobject_raw(env, class_global_ref as *mut std::ffi::c_void).unwrap_or(0);
    output_verbose(&format!(
        "[fastConstructor] {}.<init>{} class_global={:#x} class_mirror={:#x}",
        class_name, sig_str, class_global_ref as usize, class_mirror
    ));
    let constructor = FastConstructor {
        class_global_ref: class_global_ref as u64,
        class_mirror,
        art_method,
        param_types: parse_jni_param_types(&sig_str),
        shorty: make_shorty(&sig_str),
    };
    let mut constructors = fast_constructors().lock().unwrap_or_else(|e| e.into_inner());
    constructors.push(constructor);
    js_u64_to_js_number_or_bigint(ctx, constructors.len() as u64)
}

pub(crate) unsafe extern "C" fn js_java_fast_field(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return throw_type_error(ctx, b"fastField(class, field[, sig]) requires at least 2 arguments\0");
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let field_name = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let requested_sig = if argc >= 3 {
        let sig_arg = JSValue(*argv.add(2));
        if !sig_arg.is_undefined() && !sig_arg.is_null() {
            match extract_string_arg(ctx, sig_arg, b"arg 2 must be string\0") {
                Ok(s) => Some(s),
                Err(e) => return e,
            }
        } else {
            None
        }
    } else {
        None
    };

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let Some(spec) = get_art_field_spec() else {
        return throw_internal_error(ctx, "unsupported ArtField layout".to_string());
    };

    cache_fields_for_class(env, &class_name);
    let (jni_sig, field_id, is_static) = {
        let guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let Some(cache) = guard.as_ref() else {
            return throw_internal_error(ctx, format!("field cache unavailable for {}", class_name));
        };
        let Some(fields) = cache.get(&class_name) else {
            return throw_internal_error(ctx, format!("fields unavailable for {}", class_name));
        };
        let Some(info) = fields.get(&field_name) else {
            return throw_internal_error(ctx, format!("field not found: {}.{}", class_name, field_name));
        };
        (info.jni_sig.clone(), info.field_id, info.is_static)
    };

    if let Some(sig) = requested_sig.as_ref() {
        if sig != &jni_sig {
            return throw_type_error(ctx, b"field signature mismatch\0");
        }
    }
    if is_static {
        return throw_type_error(ctx, b"fastField only supports instance fields\0");
    }
    if !is_fast_field_type(&jni_sig) {
        return throw_type_error(ctx, b"fastField only supports primitive/object instance fields\0");
    }

    let cls = find_class_safe(env, &class_name);
    if cls.is_null() {
        return throw_internal_error(ctx, format!("class not found: {}", class_name));
    }
    let art_field = decode_field_id(env, cls, field_id as u64, is_static);
    jni_check_exc(env);
    if art_field == 0 {
        return throw_internal_error(ctx, format!("failed to decode field id: {}.{}", class_name, field_name));
    }
    refresh_mem_regions();
    let offset = safe_read_u32(art_field + spec.offset_offset as u64);
    if offset == 0 {
        return throw_internal_error(ctx, format!("invalid field offset: {}.{}", class_name, field_name));
    }

    let field = FastField {
        art_field,
        offset,
        is_static,
        value_type: jni_sig.as_bytes()[0],
        jni_sig,
        class_name,
        field_name,
    };
    let mut fields = fast_fields().lock().unwrap_or_else(|e| e.into_inner());
    fields.push(field);
    js_u64_to_js_number_or_bigint(ctx, fields.len() as u64)
}

pub(crate) unsafe extern "C" fn js_java_compile_method(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return throw_type_error(
            ctx,
            b"compileMethod(class, method, sig[, kind]) requires at least 3 arguments\0",
        );
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let method_name = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_str = match extract_string_arg(ctx, JSValue(*argv.add(2)), b"arg 2 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str, false)
    };
    let kind = if argc >= 4 {
        if let Some(s) = JSValue(*argv.add(3)).to_string(ctx) {
            match RequestedCompileKind::from_str(s.as_str()) {
                Some(k) => k,
                None => return throw_type_error(ctx, b"invalid compile kind\0"),
            }
        } else {
            RequestedCompileKind::Auto
        }
    } else {
        RequestedCompileKind::Auto
    };

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let (art_method, _is_static) = match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
        Ok(v) => v,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let spec = get_art_method_spec(env, art_method);
    let bridge = find_art_bridge_functions(env, spec.entry_point_offset);
    let result = compile_art_method_to_quick(env, art_method, spec.entry_point_offset, bridge, kind);

    let obj = ffi::JS_NewObject(ctx);
    let obj_v = JSValue(obj);
    obj_v.set_property(ctx, "success", JSValue::bool(result.success));
    obj_v.set_property(ctx, "compiled", JSValue::bool(result.compiled));
    obj_v.set_property(ctx, "kind", JSValue::string(ctx, result.kind));
    obj_v.set_property(ctx, "message", JSValue::string(ctx, &result.message));
    set_js_u64_property(ctx, obj, "artMethod", art_method);
    set_js_u64_property(ctx, obj, "before", result.before);
    set_js_u64_property(ctx, obj, "after", result.after);
    obj
}

pub(crate) unsafe extern "C" fn js_java_jit_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let _env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let Some(info) = probe_jit_runtime_info() else {
        return throw_internal_error(ctx, "JIT runtime info unavailable".to_string());
    };

    let obj = ffi::JS_NewObject(ctx);
    let obj_v = JSValue(obj);
    set_js_u64_property(ctx, obj, "runtime", info.runtime);
    set_js_u64_property(ctx, obj, "javaVmOffset", info.java_vm_offset as u64);
    set_js_u64_property(ctx, obj, "jitOffset", info.jit_offset as u64);
    set_js_u64_property(ctx, obj, "jitCodeCacheOffset", info.jit_code_cache_offset as u64);
    set_js_u64_property(ctx, obj, "directJit", info.direct_jit);
    set_js_u64_property(ctx, obj, "runtimeJitCodeCache", info.runtime_jit_code_cache);
    set_js_u64_property(ctx, obj, "directGetCodeCache", info.direct_get_code_cache);
    set_js_u64_property(ctx, obj, "foundJit", info.found_jit);
    obj_v.set_property(ctx, "message", JSValue::string(ctx, &info.message));
    obj
}

pub(crate) unsafe fn compile_art_method_to_quick(
    env: JniEnv,
    art_method: u64,
    entry_point_offset: usize,
    bridge: &ArtBridgeFunctions,
    kind: RequestedCompileKind,
) -> CompileResult {
    let before = read_entry_point(art_method, entry_point_offset);
    if !is_art_quick_entrypoint(before, bridge) {
        return CompileResult {
            before,
            after: before,
            success: true,
            compiled: false,
            kind: "already-quick",
            message: "method already has independent quick code".to_string(),
        };
    }

    let Some(jit) = find_jit_instance() else {
        return CompileResult {
            before,
            after: before,
            success: false,
            compiled: false,
            kind: kind.label(),
            message: "Jit* not found".to_string(),
        };
    };
    let Some(thread) = current_art_thread(env) else {
        return CompileResult {
            before,
            after: before,
            success: false,
            compiled: false,
            kind: kind.label(),
            message: "Thread::Current() unavailable".to_string(),
        };
    };
    let compile_sym = crate::jsapi::module::libart_dlsym(
        "_ZN3art3jit3Jit13CompileMethodEPNS_9ArtMethodEPNS_6ThreadENS_15CompilationKindEb",
    );
    if compile_sym.is_null() {
        return CompileResult {
            before,
            after: before,
            success: false,
            compiled: false,
            kind: kind.label(),
            message: "Jit::CompileMethod symbol not found".to_string(),
        };
    }

    type CompileMethodFn =
        unsafe extern "C" fn(this: u64, method: u64, thread: u64, compilation_kind: u32, prejit: u8) -> u8;
    let compile_method: CompileMethodFn = std::mem::transmute(compile_sym);

    let mut last_kind = kind.label();
    let mut saw_compile_success = false;
    for k in kind.sequence() {
        last_kind = match *k {
            1 => "fast",
            2 => "baseline",
            3 => "optimized",
            _ => "unknown",
        };
        let ok = compile_method(jit, art_method, thread, *k, 0) != 0;
        let after = read_entry_point(art_method, entry_point_offset);
        if ok {
            saw_compile_success = true;
        }
        if !is_art_quick_entrypoint(after, bridge) {
            return CompileResult {
                before,
                after,
                success: true,
                compiled: true,
                kind: last_kind,
                message: format!("Jit::CompileMethod({}) succeeded", last_kind),
            };
        }
    }

    let after = read_entry_point(art_method, entry_point_offset);
    CompileResult {
        before,
        after,
        success: false,
        compiled: saw_compile_success,
        kind: last_kind,
        message: if saw_compile_success {
            "JIT reported success but entrypoint is still a shared ART bridge".to_string()
        } else {
            "Jit::CompileMethod returned false".to_string()
        },
    }
}

unsafe fn current_art_thread(env: JniEnv) -> Option<u64> {
    let sym = crate::jsapi::module::libart_dlsym("_ZN3art6Thread7CurrentEv");
    if !sym.is_null() {
        type ThreadCurrentFn = unsafe extern "C" fn() -> u64;
        let thread_current: ThreadCurrentFn = std::mem::transmute(sym);
        let thread = thread_current() & super::PAC_STRIP_MASK;
        if thread != 0 {
            return Some(thread);
        }
    }
    if !env.is_null() {
        let thread = *((env as usize + 8) as *const u64) & super::PAC_STRIP_MASK;
        if thread != 0 {
            return Some(thread);
        }
    }
    None
}

type ArtMethodInvokeFn = unsafe extern "C" fn(
    method: *mut std::ffi::c_void,
    thread: *mut std::ffi::c_void,
    args: *mut u32,
    args_size: u32,
    result: *mut u64,
    shorty: *const std::os::raw::c_char,
);

static ART_METHOD_INVOKE: OnceLock<Option<ArtMethodInvokeFn>> = OnceLock::new();

pub(crate) unsafe fn invoke_fast_method_raw_on_thread(
    method: &FastMethod,
    thread: u64,
    receiver: u64,
    args: &[u64],
) -> Result<u64, String> {
    if thread == 0 {
        return Err("current ART Thread is null".to_string());
    }
    if !method.is_static && receiver == 0 {
        return Err("jcall instance receiver is null".to_string());
    }
    if args.len() != method.param_types.len() {
        return Err(format!(
            "jcall argument count mismatch: expected {}, got {}",
            method.param_types.len(),
            args.len()
        ));
    }

    let mut invoke_args = StackArtInvokeArgs::new();
    if !method.is_static {
        invoke_args.push("L", receiver)?;
    }
    for (i, type_sig) in method.param_types.iter().enumerate() {
        invoke_args.push(type_sig.as_str(), args[i])?;
    }
    let before_exception = thread_exception(thread);
    let ret = invoke_fast_method_art_ready_raw(method, thread, invoke_args.as_mut_ptr(), invoke_args.size_bytes())?;
    if clear_new_thread_exception(thread, before_exception) {
        return Err("ArtMethod::Invoke method raised exception".to_string());
    }
    Ok(ret)
}

pub(crate) unsafe fn fast_method_receiver_is_exact(method: &FastMethod, receiver: u64) -> bool {
    method.is_static || object_class_matches(receiver, method.class_mirror)
}

unsafe fn object_class_matches(obj: u64, class_mirror: u64) -> bool {
    if obj == 0 || class_mirror == 0 {
        return false;
    }
    let compressed_class = std::ptr::read_volatile(obj as *const u32) as u64;
    compressed_class == (class_mirror & 0xffff_ffff)
}

unsafe fn invoke_fast_method_art_ready_raw(
    method: &FastMethod,
    thread: u64,
    args: *mut u32,
    args_size: u32,
) -> Result<u64, String> {
    let Some(invoke) = art_method_invoke() else {
        return Err("ArtMethod::Invoke symbol not found".to_string());
    };
    let mut result = 0u64;
    invoke(
        method.art_method as *mut std::ffi::c_void,
        thread as *mut std::ffi::c_void,
        args,
        args_size,
        &mut result as *mut u64,
        method.shorty.as_ptr(),
    );
    Ok(result)
}

pub(crate) unsafe fn invoke_fast_constructor_raw_on_thread(
    ctor: &FastConstructor,
    thread: u64,
    receiver: u64,
    args: &[u64],
) -> Result<(), String> {
    if thread == 0 {
        return Err("current ART Thread is null".to_string());
    }
    if receiver == 0 {
        return Err("jnew receiver allocation returned null".to_string());
    }
    if args.len() != ctor.param_types.len() {
        return Err(format!(
            "jnew argument count mismatch: expected {}, got {}",
            ctor.param_types.len(),
            args.len()
        ));
    }

    let mut invoke_args = StackArtInvokeArgs::new();
    invoke_args.push("L", receiver)?;
    for (i, type_sig) in ctor.param_types.iter().enumerate() {
        invoke_args.push(type_sig.as_str(), args[i])?;
    }
    let before_exception = thread_exception(thread);
    invoke_fast_constructor_art_ready_raw(ctor, thread, invoke_args.as_mut_ptr(), invoke_args.size_bytes())?;
    if clear_new_thread_exception(thread, before_exception) {
        return Err("ArtMethod::Invoke constructor raised exception".to_string());
    }
    Ok(())
}

unsafe fn invoke_fast_constructor_art_ready_raw(
    ctor: &FastConstructor,
    thread: u64,
    args: *mut u32,
    args_size: u32,
) -> Result<(), String> {
    let Some(invoke) = art_method_invoke() else {
        return Err("ArtMethod::Invoke symbol not found".to_string());
    };
    let mut result = 0u64;
    invoke(
        ctor.art_method as *mut std::ffi::c_void,
        thread as *mut std::ffi::c_void,
        args,
        args_size,
        &mut result as *mut u64,
        ctor.shorty.as_ptr(),
    );
    Ok(())
}

pub(crate) unsafe fn with_fast_art_handle_scope<R>(thread: u64, f: impl FnOnce() -> R) -> R {
    FAST_ART_HANDLE_SCOPE_ENTER.fetch_add(1, Ordering::Relaxed);
    let env = get_thread_env().unwrap_or(std::ptr::null_mut());
    if env.is_null() {
        FAST_ART_HANDLE_SCOPE_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
        return f();
    }
    let Some(spec) = super::art_thread::get_art_thread_spec(env) else {
        FAST_ART_HANDLE_SCOPE_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
        return f();
    };
    if thread == 0 {
        FAST_ART_HANDLE_SCOPE_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
        return f();
    }

    let top_addr = (thread as usize + spec.top_handle_scope_offset) as *mut u64;
    let previous_top = std::ptr::read_volatile(top_addr);
    let mut scope = FastArtHandleScope::new(previous_top);
    let scope_ptr = &mut scope as *mut FastArtHandleScope;
    std::ptr::write_volatile(top_addr, scope_ptr as u64);
    let previous_tls = CURRENT_FAST_ART_HANDLE_SCOPE.with(|current| {
        let previous = current.get();
        current.set(scope_ptr);
        previous
    });

    let result = f();

    let used_roots = (*scope_ptr).size as u64;
    update_fast_max(&FAST_ART_HANDLE_SCOPE_MAX_ROOTS, used_roots);
    CURRENT_FAST_ART_HANDLE_SCOPE.with(|current| current.set(previous_tls));
    let current_top = std::ptr::read_volatile(top_addr);
    if current_top == scope_ptr as u64 {
        std::ptr::write_volatile(top_addr, previous_top);
    } else {
        FAST_ART_HANDLE_SCOPE_LEAKED.fetch_add(1, Ordering::Relaxed);
        std::ptr::write_volatile(top_addr, previous_top);
        return result;
    }
    result
}

pub(crate) unsafe fn root_fast_raw_object_for_callback(raw: u64) -> Result<FastArtRoot, String> {
    if raw == 0 {
        return Err("cannot root null raw object".to_string());
    }
    if raw > u32::MAX as u64 {
        return Err(format!("raw object is not a compressed ART reference: {:#x}", raw));
    }
    CURRENT_FAST_ART_HANDLE_SCOPE.with(|current| {
        let scope = current.get();
        if scope.is_null() {
            FAST_ART_HANDLE_SCOPE_ROOT_FAILED.fetch_add(1, Ordering::Relaxed);
            return Err("fast ART handle scope unavailable".to_string());
        }
        let scope = &mut *scope;
        let slot = scope.size as usize;
        if slot >= FAST_ART_HANDLE_SCOPE_CAPACITY {
            FAST_ART_HANDLE_SCOPE_ROOT_FAILED.fetch_add(1, Ordering::Relaxed);
            FAST_ART_HANDLE_SCOPE_CAPACITY_EXCEEDED.fetch_add(1, Ordering::Relaxed);
            return Err("fast ART handle scope capacity exceeded".to_string());
        }
        scope.refs[slot] = raw as u32;
        scope.size += 1;
        Ok(FastArtRoot { slot: slot as u32 })
    })
}

pub(crate) unsafe fn read_fast_art_root(root: FastArtRoot) -> Option<u64> {
    CURRENT_FAST_ART_HANDLE_SCOPE.with(|current| {
        let scope = current.get();
        if scope.is_null() {
            return None;
        }
        let scope = &*scope;
        let slot = root.slot as usize;
        if slot >= scope.size as usize || slot >= FAST_ART_HANDLE_SCOPE_CAPACITY {
            None
        } else {
            Some(scope.refs[slot] as u64)
        }
    })
}

unsafe fn art_method_invoke() -> Option<ArtMethodInvokeFn> {
    *ART_METHOD_INVOKE.get_or_init(|| {
        let sym = crate::jsapi::module::libart_dlsym("_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc");
        if sym.is_null() {
            None
        } else {
            Some(std::mem::transmute(sym))
        }
    })
}

struct StackArtInvokeArgs {
    words: [u32; FAST_ART_STACK_INVOKE_WORDS],
    len: usize,
}

impl StackArtInvokeArgs {
    fn new() -> Self {
        Self {
            words: [0; FAST_ART_STACK_INVOKE_WORDS],
            len: 0,
        }
    }

    fn push(&mut self, type_sig: &str, raw: u64) -> Result<(), String> {
        match type_sig.as_bytes().first().copied() {
            Some(b'J' | b'D') => {
                self.push_word(raw as u32)?;
                self.push_word((raw >> 32) as u32)
            }
            Some(b'F') => self.push_word(raw as u32),
            Some(b'L' | b'[') => self.push_word(raw as u32),
            _ => self.push_word(raw as u32),
        }
    }

    fn push_word(&mut self, word: u32) -> Result<(), String> {
        if self.len >= self.words.len() {
            return Err("ArtMethod::Invoke argument buffer exceeded fast stack capacity".to_string());
        }
        self.words[self.len] = word;
        self.len += 1;
        Ok(())
    }

    fn as_mut_ptr(&mut self) -> *mut u32 {
        self.words.as_mut_ptr()
    }

    fn size_bytes(&self) -> u32 {
        (self.len * std::mem::size_of::<u32>()) as u32
    }
}

pub(crate) unsafe fn alloc_fast_object_quick_on_thread(thread: u64, class_mirror: u64) -> Option<u64> {
    if thread == 0 || class_mirror == 0 {
        FAST_TLAB_ALLOC_MISS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let size_offset = super::heap_scan::resolve_class_object_size_offset();
    let object_size = std::ptr::read_volatile((class_mirror as usize + size_offset) as *const u32);
    if object_size == 0 || object_size > MAX_TLAB_FAST_OBJECT_SIZE || object_size % 8 != 0 {
        FAST_TLAB_ALLOC_MISS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let pos_addr = (thread as usize + THREAD_LOCAL_POS_OFFSET) as *mut u64;
    let end_addr = (thread as usize + THREAD_LOCAL_END_OFFSET) as *const u64;
    let pos = std::ptr::read_volatile(pos_addr);
    let end = std::ptr::read_volatile(end_addr);
    let Some(next) = pos.checked_add(object_size as u64) else {
        FAST_TLAB_ALLOC_MISS.fetch_add(1, Ordering::Relaxed);
        return alloc_fast_object_quick_slow_on_thread(thread, class_mirror);
    };
    if pos == 0 || next > end {
        FAST_TLAB_ALLOC_MISS.fetch_add(1, Ordering::Relaxed);
        return alloc_fast_object_quick_slow_on_thread(thread, class_mirror);
    }
    std::ptr::write_volatile(pos_addr, next);
    std::ptr::write_bytes(pos as *mut u8, 0, object_size as usize);
    std::ptr::write_volatile(
        (pos as usize + MIRROR_OBJECT_CLASS_OFFSET) as *mut u32,
        class_mirror as u32,
    );
    std::ptr::write_volatile((pos as usize + MIRROR_OBJECT_LOCK_WORD_OFFSET) as *mut u32, 0);
    std::sync::atomic::fence(Ordering::Release);
    FAST_TLAB_ALLOC_HIT.fetch_add(1, Ordering::Relaxed);
    Some(pos)
}

unsafe fn alloc_fast_object_quick_slow_on_thread(thread: u64, class_mirror: u64) -> Option<u64> {
    if thread == 0 || class_mirror == 0 {
        return None;
    }
    let entry = quick_entrypoint(thread as usize, QUICK_ALLOC_OBJECT_INITIALIZED_INDEX)?;
    FAST_QUICK_ALLOC_SLOW_PATH.fetch_add(1, Ordering::Relaxed);
    let before_exception = thread_exception(thread);
    let raw = call_quick_alloc_object(entry as usize, thread as usize, class_mirror as usize) as u64;
    if clear_new_thread_exception(thread, before_exception) {
        return None;
    }
    (raw != 0).then_some(raw)
}

#[inline]
pub(crate) unsafe fn fast_art_exception_stats() -> (u64, u64) {
    (
        FAST_ART_EXCEPTION_SEEN.load(Ordering::Acquire),
        FAST_ART_EXCEPTION_CLEARED.load(Ordering::Acquire),
    )
}

#[inline]
pub(crate) unsafe fn fast_art_handle_scope_stats() -> (u64, u64, u64, u64, u64, u64) {
    (
        FAST_ART_HANDLE_SCOPE_ENTER.load(Ordering::Acquire),
        FAST_ART_HANDLE_SCOPE_UNAVAILABLE.load(Ordering::Acquire),
        FAST_ART_HANDLE_SCOPE_LEAKED.load(Ordering::Acquire),
        FAST_ART_HANDLE_SCOPE_MAX_ROOTS.load(Ordering::Acquire),
        FAST_ART_HANDLE_SCOPE_ROOT_FAILED.load(Ordering::Acquire),
        FAST_ART_HANDLE_SCOPE_CAPACITY_EXCEEDED.load(Ordering::Acquire),
    )
}

#[inline]
pub(crate) unsafe fn fast_tlab_alloc_stats() -> (u64, u64, u64) {
    (
        FAST_TLAB_ALLOC_HIT.load(Ordering::Acquire),
        FAST_TLAB_ALLOC_MISS.load(Ordering::Acquire),
        FAST_QUICK_ALLOC_SLOW_PATH.load(Ordering::Acquire),
    )
}

#[inline]
unsafe fn thread_exception(thread: u64) -> u64 {
    if thread == 0 {
        return 0;
    }
    std::ptr::read_volatile((thread as usize + THREAD_EXCEPTION_OFFSET) as *const u64)
}

#[inline]
unsafe fn clear_new_thread_exception(thread: u64, before_exception: u64) -> bool {
    if thread == 0 {
        return false;
    }
    let exception_addr = (thread as usize + THREAD_EXCEPTION_OFFSET) as *mut u64;
    let after_exception = std::ptr::read_volatile(exception_addr);
    if after_exception == 0 || after_exception == before_exception {
        return false;
    }
    FAST_ART_EXCEPTION_SEEN.fetch_add(1, Ordering::Relaxed);
    if before_exception == 0 {
        std::ptr::write_volatile(exception_addr, 0);
        FAST_ART_EXCEPTION_CLEARED.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    false
}

unsafe fn quick_entrypoint(thread: usize, index: usize) -> Option<u64> {
    if thread == 0 || index >= QUICK_ENTRYPOINT_COUNT {
        return None;
    }
    let cached = QUICK_ENTRYPOINTS_OFFSET.load(Ordering::Acquire);
    if cached == QUICK_ENTRYPOINTS_OFFSET_FAILED {
        return None;
    }
    if cached != 0 {
        let off = cached - 1;
        let entry = std::ptr::read_volatile((thread + off + index * 8) as *const u64);
        return crate::jsapi::module::is_in_libart(entry).then_some(entry);
    }

    let max_off = QUICK_SCAN_LIMIT.saturating_sub(QUICK_ENTRYPOINT_COUNT * 8);
    for off in (0..=max_off).step_by(8) {
        let base = (thread + off) as *const u64;
        let start = std::ptr::read_volatile(base.add(QUICK_JNI_METHOD_START_INDEX));
        let end = std::ptr::read_volatile(base.add(QUICK_JNI_METHOD_END_INDEX));
        if !crate::jsapi::module::is_in_libart(start) || !crate::jsapi::module::is_in_libart(end) {
            continue;
        }
        if off < 16 {
            continue;
        }
        let prev0 = std::ptr::read_volatile((thread + off - 16) as *const u64);
        let prev1 = std::ptr::read_volatile((thread + off - 8) as *const u64);
        if !crate::jsapi::module::is_in_libart(prev0) || !crate::jsapi::module::is_in_libart(prev1) {
            continue;
        }

        let mut libart_ptrs = 0usize;
        for i in 0..QUICK_ENTRYPOINT_COUNT {
            if crate::jsapi::module::is_in_libart(std::ptr::read_volatile(base.add(i))) {
                libart_ptrs += 1;
            }
        }
        if libart_ptrs < QUICK_MIN_LIBART_POINTERS {
            continue;
        }

        QUICK_ENTRYPOINTS_OFFSET.store(off + 1, Ordering::Release);
        let entry = std::ptr::read_volatile(base.add(index));
        return crate::jsapi::module::is_in_libart(entry).then_some(entry);
    }

    QUICK_ENTRYPOINTS_OFFSET.store(QUICK_ENTRYPOINTS_OFFSET_FAILED, Ordering::Release);
    None
}

#[cfg(target_arch = "aarch64")]
unsafe fn call_quick_alloc_object(entry: usize, thread: usize, klass: usize) -> usize {
    let mut ret = klass;
    core::arch::asm!(
        "str x19, [sp, #-16]!",
        "mov x19, x10",
        "blr x11",
        "ldr x19, [sp], #16",
        in("x10") thread,
        in("x11") entry,
        inlateout("x0") ret,
        clobber_abi("C"),
    );
    ret
}

#[cfg(not(target_arch = "aarch64"))]
unsafe fn call_quick_alloc_object(entry: usize, _thread: usize, klass: usize) -> usize {
    let f: unsafe extern "C" fn(usize) -> usize = std::mem::transmute(entry);
    f(klass)
}
