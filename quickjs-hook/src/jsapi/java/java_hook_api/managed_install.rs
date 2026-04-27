use crate::ffi;
use crate::jsapi::callback_util::{throw_internal_error, with_registry_mut};
use crate::jsapi::console::output_message;
use crate::value::JSValue;
use std::ffi::CString;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use super::super::art_controller::{ensure_art_controller_initialized, refresh_walkstack_sigsegv_guard};
use super::super::art_method::*;
use super::super::callback::*;
use super::super::java_lua_fast_api::{compile_art_method_to_quick, RequestedCompileKind};
use super::super::jni_core::*;
use super::super::reflect::{decode_method_id, find_class_safe, get_app_classloader_local_ref};
use super::install_support::{create_class_global_ref, update_original_method_flags_for_hook, JavaHookInstallGuard};
use super::managed_dex_builder::{build_managed_dsl_dex, GeneratedStringLiteral};

struct DynamicManagedHelperRefs {
    class_global_ref: u64,
    loader_global_ref: u64,
    dex_bytes: Vec<u8>,
}

static DYNAMIC_MANAGED_HELPER_REFS: Mutex<Vec<DynamicManagedHelperRefs>> = Mutex::new(Vec::new());
static DYNAMIC_MANAGED_CLASS_ID: AtomicU64 = AtomicU64::new(1);

unsafe fn load_dynamic_managed_helper_class(
    env: JniEnv,
    dex_bytes: Vec<u8>,
    helper_class_name: &str,
) -> Result<*mut std::ffi::c_void, String> {
    let slot_index = {
        let mut refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
        let idx = refs.len();
        refs.push(DynamicManagedHelperRefs {
            class_global_ref: 0,
            loader_global_ref: 0,
            dex_bytes,
        });
        idx
    };

    let (dex_ptr, dex_len) = {
        let refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
        let dex = &refs[slot_index].dex_bytes;
        (dex.as_ptr() as *mut std::ffi::c_void, dex.len() as i64)
    };

    let find_loader_cls = find_class_safe(env, "dalvik/system/InMemoryDexClassLoader");
    if find_loader_cls.is_null() {
        return Err("InMemoryDexClassLoader class not found".to_string());
    }

    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let new_object: NewObjectAFn = jni_fn!(env, NewObjectAFn, JNI_NEW_OBJECT_A);
    let new_direct: NewDirectByteBufferFn = jni_fn!(env, NewDirectByteBufferFn, JNI_NEW_DIRECT_BYTE_BUFFER);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let new_string_utf: NewStringUtfFn = jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);

    let ctor_name = CString::new("<init>").unwrap();
    let ctor_sig = CString::new("(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V").unwrap();
    let ctor = get_mid(env, find_loader_cls, ctor_name.as_ptr(), ctor_sig.as_ptr());
    if ctor.is_null() || jni_check_exc(env) {
        delete_local_ref(env, find_loader_cls);
        return Err("InMemoryDexClassLoader(ByteBuffer, ClassLoader) constructor not found".to_string());
    }

    let dex_buf = new_direct(env, dex_ptr, dex_len);
    if dex_buf.is_null() || jni_check_exc(env) {
        delete_local_ref(env, find_loader_cls);
        return Err("NewDirectByteBuffer for dynamic managed dex failed".to_string());
    }

    let parent_loader = get_app_classloader_local_ref(env);
    let args = [dex_buf as u64, parent_loader as u64];
    let loader = new_object(env, find_loader_cls, ctor, args.as_ptr() as *const std::ffi::c_void);
    if loader.is_null() || jni_check_exc(env) {
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err("new dynamic InMemoryDexClassLoader failed".to_string());
    }

    let class_loader_cls = find_class_safe(env, "java/lang/ClassLoader");
    if class_loader_cls.is_null() {
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err("java.lang.ClassLoader class not found".to_string());
    }
    let load_name = CString::new("loadClass").unwrap();
    let load_sig = CString::new("(Ljava/lang/String;)Ljava/lang/Class;").unwrap();
    let load_mid = get_mid(env, class_loader_cls, load_name.as_ptr(), load_sig.as_ptr());
    if load_mid.is_null() || jni_check_exc(env) {
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err("ClassLoader.loadClass method not found".to_string());
    }

    let helper_name = CString::new(helper_class_name).map_err(|_| "invalid helper class name".to_string())?;
    let helper_jstr = new_string_utf(env, helper_name.as_ptr());
    if helper_jstr.is_null() || jni_check_exc(env) {
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err("NewStringUTF for dynamic helper class failed".to_string());
    }
    let load_args = [helper_jstr as u64];
    let helper_cls = call_obj(env, loader, load_mid, load_args.as_ptr() as *const std::ffi::c_void);
    delete_local_ref(env, helper_jstr);
    if helper_cls.is_null() || jni_check_exc(env) {
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err("dynamic managed helper loadClass failed".to_string());
    }

    let helper_global = new_global_ref(env, helper_cls);
    let loader_global = new_global_ref(env, loader);
    if helper_global.is_null() || loader_global.is_null() || jni_check_exc(env) {
        delete_local_ref(env, helper_cls);
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err("dynamic helper global ref creation failed".to_string());
    }

    {
        let mut refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = refs.get_mut(slot_index) {
            slot.class_global_ref = helper_global as u64;
            slot.loader_global_ref = loader_global as u64;
        }
    }

    delete_local_ref(env, class_loader_cls);
    delete_local_ref(env, loader);
    if !parent_loader.is_null() {
        delete_local_ref(env, parent_loader);
    }
    delete_local_ref(env, dex_buf);
    delete_local_ref(env, find_loader_cls);

    Ok(helper_cls)
}

unsafe fn initialize_generated_string_literals(
    env: JniEnv,
    helper_cls: *mut std::ffi::c_void,
    literals: &[GeneratedStringLiteral],
) -> Result<(), String> {
    if literals.is_empty() {
        return Ok(());
    }

    let get_static_field_id: GetStaticFieldIdFn = jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
    type SetStaticObjectFieldFn =
        unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void);
    let set_static_object_field: SetStaticObjectFieldFn =
        jni_fn!(env, SetStaticObjectFieldFn, JNI_SET_STATIC_OBJECT_FIELD);
    let new_string_utf: NewStringUtfFn = jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let string_sig = CString::new("Ljava/lang/String;").unwrap();

    for lit in literals {
        let field_name = CString::new(lit.field_name.as_str())
            .map_err(|_| format!("invalid generated string field name {}", lit.field_name))?;
        let field_id = get_static_field_id(env, helper_cls, field_name.as_ptr(), string_sig.as_ptr());
        if field_id.is_null() || jni_check_exc(env) {
            return Err(format!("generated string field {} not found", lit.field_name));
        }

        let value = CString::new(lit.value.as_str())
            .map_err(|_| format!("string literal for {} contains NUL byte", lit.field_name))?;
        let jstr = new_string_utf(env, value.as_ptr());
        if jstr.is_null() || jni_check_exc(env) {
            return Err(format!(
                "NewStringUTF failed for generated string field {}",
                lit.field_name
            ));
        }
        set_static_object_field(env, helper_cls, field_id, jstr);
        delete_local_ref(env, jstr);
        if jni_check_exc(env) {
            return Err(format!(
                "SetStaticObjectField failed for generated string field {}",
                lit.field_name
            ));
        }
    }
    output_message(&format!(
        "[managedHook] initialized {} generated string literal field(s)",
        literals.len()
    ));
    Ok(())
}

unsafe fn install_orig_backup_art_method(
    backup_art_method: u64,
    original_art_method: u64,
    entry_point_offset: usize,
    original_trampoline: u64,
) -> Result<(), String> {
    if backup_art_method == 0 || original_art_method == 0 || original_trampoline == 0 {
        return Err("invalid managed orig backup ArtMethod state".to_string());
    }

    std::ptr::write_volatile(
        (backup_art_method as usize + entry_point_offset) as *mut u64,
        original_trampoline,
    );
    crate::ffi::hook::hook_flush_cache(
        (backup_art_method as usize + entry_point_offset) as *mut std::ffi::c_void,
        8,
    );
    output_message(&format!(
        "[managedHook] installed orig backup entry ArtMethod={:#x} source={:#x} entry={:#x}",
        backup_art_method, original_art_method, original_trampoline
    ));
    Ok(())
}

unsafe fn install_managed_method_helper(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    actual_sig: &str,
    helper_cls: *mut std::ffi::c_void,
    helper_method_name_str: &str,
    helper_method_sig_str: &str,
    orig_backup_name_sig: Option<(&str, &str)>,
    label: &str,
    uses_orig: bool,
) -> Result<(), String> {
    let (art_method, _is_static) = resolve_art_method(env, class_name, method_name, actual_sig, false)?;

    init_java_registry();
    if crate::jsapi::callback_util::with_registry(&JAVA_HOOK_REGISTRY, |r| r.contains_key(&art_method)).unwrap_or(false)
    {
        return Err(format!(
            "{}.{}{} already hooked — unhook first",
            class_name, method_name, actual_sig
        ));
    }

    let get_static_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
    let helper_method_sig = CString::new(helper_method_sig_str).unwrap();
    let helper_method_name = CString::new(helper_method_name_str).unwrap();
    let helper_method_id = get_static_mid(env, helper_cls, helper_method_name.as_ptr(), helper_method_sig.as_ptr());
    if helper_method_id.is_null() || jni_check_exc(env) {
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
        delete_local_ref(env, helper_cls);
        return Err(format!("managed helper {} method not found", helper_method_name_str));
    }
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let helper_art_method = decode_method_id(env, helper_cls, helper_method_id as u64, true);
    if helper_art_method == 0 {
        delete_local_ref(env, helper_cls);
        return Err("managed helper ArtMethod decode failed".to_string());
    }
    let orig_backup_art_method = if let Some((backup_name_str, backup_sig_str)) = orig_backup_name_sig {
        let backup_name = CString::new(backup_name_str).unwrap();
        let backup_sig = CString::new(backup_sig_str).unwrap();
        let backup_method_id = get_static_mid(env, helper_cls, backup_name.as_ptr(), backup_sig.as_ptr());
        if backup_method_id.is_null() || jni_check_exc(env) {
            delete_local_ref(env, helper_cls);
            return Err(format!("managed helper {} method not found", backup_name_str));
        }
        let art_method = decode_method_id(env, helper_cls, backup_method_id as u64, true);
        if art_method == 0 {
            delete_local_ref(env, helper_cls);
            return Err("managed helper orig backup ArtMethod decode failed".to_string());
        }
        Some(art_method)
    } else {
        None
    };

    let spec = get_art_method_spec(env, art_method);
    let ep_offset = spec.entry_point_offset;
    let data_off = spec.data_offset;
    let original_access_flags = std::ptr::read_volatile((art_method as usize + spec.access_flags_offset) as *const u32);
    let original_data = std::ptr::read_volatile((art_method as usize + data_off) as *const u64);
    let mut original_entry_point = read_entry_point(art_method, ep_offset);
    let bridge = find_art_bridge_functions(env, ep_offset);

    if is_art_quick_entrypoint(original_entry_point, bridge) {
        let compile = compile_art_method_to_quick(env, art_method, ep_offset, bridge, RequestedCompileKind::Auto);
        output_message(&format!(
            "[managedHook] compile original {}.{}{}: success={} compiled={} before={:#x} after={:#x} {}",
            class_name,
            method_name,
            actual_sig,
            compile.success,
            compile.compiled,
            compile.before,
            compile.after,
            compile.message
        ));
        original_entry_point = read_entry_point(art_method, ep_offset);
    }
    if is_art_quick_entrypoint(original_entry_point, bridge) {
        return Err(format!(
            "{}.{}{} still has shared ART entrypoint after compile",
            class_name, method_name, actual_sig
        ));
    }

    let helper_spec = get_art_method_spec(env, helper_art_method);
    let helper_compile = compile_art_method_to_quick(
        env,
        helper_art_method,
        helper_spec.entry_point_offset,
        bridge,
        RequestedCompileKind::Auto,
    );
    output_message(&format!(
        "[managedHook] compile helper: success={} compiled={} before={:#x} after={:#x} {}",
        helper_compile.success,
        helper_compile.compiled,
        helper_compile.before,
        helper_compile.after,
        helper_compile.message
    ));
    if is_art_quick_entrypoint(
        read_entry_point(helper_art_method, helper_spec.entry_point_offset),
        bridge,
    ) {
        return Err("managed helper still has shared ART entrypoint after compile".to_string());
    }
    let helper_entry_point = read_entry_point(helper_art_method, helper_spec.entry_point_offset);
    if let Some(backup_art_method) = orig_backup_art_method {
        install_orig_backup_art_method(backup_art_method, art_method, ep_offset, original_entry_point)?;
    }
    let class_global_ref = create_class_global_ref(env, class_name)?;
    let mut install_guard = JavaHookInstallGuard::new(
        art_method,
        spec.access_flags_offset,
        data_off,
        ep_offset,
        original_access_flags,
        original_data,
        original_entry_point,
        class_global_ref,
    );

    ensure_art_controller_initialized(&bridge, ep_offset, env as *mut std::ffi::c_void);
    update_original_method_flags_for_hook(art_method, spec.access_flags_offset, original_access_flags);
    install_guard.set_original_method_mutated();

    let (per_method_hook_target, quick_trampoline) = if uses_orig {
        let mut resolved_target: *mut std::ffi::c_void = std::ptr::null_mut();
        let managed_entry = crate::ffi::hook::hook_install_managed_direct_entrypoint(
            original_entry_point as *mut std::ffi::c_void,
            env as *mut std::ffi::c_void,
            &mut resolved_target,
            helper_art_method,
            helper_entry_point,
            art_method,
            0,
        );
        if managed_entry.is_null() {
            delete_local_ref(env, helper_cls);
            return Err("hook_install_managed_direct_entrypoint failed".to_string());
        }
        let backup_entry = if !resolved_target.is_null() {
            resolved_target as u64
        } else {
            original_entry_point
        };
        std::ptr::write_volatile((art_method as usize + ep_offset) as *mut u64, managed_entry as u64);
        crate::ffi::hook::hook_flush_cache((art_method as usize + ep_offset) as *mut std::ffi::c_void, 8);
        output_message(&format!(
            "[managedHook] installed entrypoint managed thunk original={:#x} entry={:#x} backup_entry={:#x}",
            art_method, managed_entry as u64, backup_entry
        ));
        (None, backup_entry)
    } else {
        let (hook_addr, stealth_flag) =
            super::super::art_controller::prepare_hook_target(original_entry_point, env as *mut std::ffi::c_void)
                .map_err(|e| format!("prepare_hook_target: {}", e))?;
        let mut hooked_target: *mut std::ffi::c_void = std::ptr::null_mut();
        let quick_trampoline = crate::ffi::hook::hook_install_managed_direct_router(
            hook_addr as *mut std::ffi::c_void,
            stealth_flag,
            env as *mut std::ffi::c_void,
            &mut hooked_target,
            helper_art_method,
            helper_entry_point,
            art_method,
            if uses_orig { 1 } else { 0 },
        );
        if quick_trampoline.is_null() {
            delete_local_ref(env, helper_cls);
            return Err("hook_install_managed_direct_router failed".to_string());
        }
        super::super::art_controller::try_fixup_trampoline_pub(quick_trampoline, original_entry_point);
        let per_method_hook_target = if !hooked_target.is_null() {
            Some(hooked_target as u64)
        } else {
            Some(original_entry_point)
        };
        (per_method_hook_target, quick_trampoline as u64)
    };
    delete_local_ref(env, helper_cls);
    let use_blr = false;

    with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
        registry.insert(
            art_method,
            JavaHookData {
                art_method,
                original_access_flags,
                original_entry_point,
                original_data,
                hook_type: HookType::Managed {
                    replacement_art_method: helper_art_method,
                    sentinel_addr: 0,
                    per_method_hook_target,
                },
                clone_addr: 0,
                class_global_ref,
                return_type: get_return_type_from_sig(actual_sig),
                return_type_sig: get_return_type_sig(actual_sig),
                ctx: 0,
                callback_bytes: [0u8; 16],
                method_key: method_key(class_name, method_name, actual_sig),
                is_static: false,
                param_count: count_jni_params(actual_sig),
                param_types: parse_jni_param_types(actual_sig),
                class_name: class_name.to_string(),
                quick_trampoline,
                use_blr,
            },
        );
    });

    cache_fields_for_class(env, class_name);
    output_message(&format!(
        "[managedHook] installed {} {}.{}{} -> helper ArtMethod={:#x}, original={:#x}, trampoline={:#x}",
        label, class_name, method_name, actual_sig, helper_art_method, art_method, quick_trampoline
    ));

    install_guard.commit();
    Ok(())
}

unsafe fn install_managed_dsl_inner(class_name: &str, method_name: &str, sig: &str, dsl: &str) -> Result<(), String> {
    let env = ensure_jni_initialized()?;
    let (_, is_static) = resolve_art_method(env, class_name, method_name, sig, false)?;
    let class_id = DYNAMIC_MANAGED_CLASS_ID.fetch_add(1, Ordering::Relaxed);
    let generated = build_managed_dsl_dex(env, class_id, class_name, method_name, sig, is_static, dsl)?;
    output_message(&format!(
        "[managedHook] generated generic DSL dex class={} target={}.{}{} static={} dexSize={}",
        generated.class_name,
        class_name,
        method_name,
        sig,
        is_static,
        generated.dex.len()
    ));
    let helper_cls = load_dynamic_managed_helper_class(env, generated.dex, &generated.class_name)?;
    initialize_generated_string_literals(env, helper_cls, &generated.string_literals)?;
    install_managed_method_helper(
        env,
        class_name,
        method_name,
        sig,
        helper_cls,
        &generated.method_name,
        &generated.method_sig,
        generated
            .orig_backup_name
            .as_deref()
            .zip(generated.orig_backup_sig.as_deref()),
        "generic-dsl",
        generated.uses_orig,
    )?;
    refresh_walkstack_sigsegv_guard();
    Ok(())
}

unsafe fn extract_string_prop(
    ctx: *mut ffi::JSContext,
    obj: JSValue,
    names: &[&str],
    api: &str,
) -> Result<String, ffi::JSValue> {
    for name in names {
        let value = obj.get_property(ctx, name);
        if !value.is_undefined() && !value.is_null() {
            let result = value.to_string(ctx);
            value.free(ctx);
            if let Some(result) = result {
                return Ok(result);
            }
            return Err(throw_internal_error(
                ctx,
                format!("{} option '{}' must be a string", api, name),
            ));
        }
        value.free(ctx);
    }
    Err(throw_internal_error(
        ctx,
        format!("{} option missing: {}", api, names.join("/")),
    ))
}

unsafe fn extract_managed_hook_dsl_args(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> Result<(String, String, String, String), ffi::JSValue> {
    if argc == 1 {
        let opts = JSValue(*argv);
        if !opts.is_object() || ffi::JS_IsArray(ctx, opts.raw()) != 0 {
            return Err(ffi::JS_ThrowTypeError(
                ctx,
                b"Java.managedHookDsl(object) requires an options object\0".as_ptr() as *const _,
            ));
        }
        let class_name = extract_string_prop(ctx, opts, &["className", "class"], "managedHookDsl")?;
        let method_name = extract_string_prop(ctx, opts, &["methodName", "method"], "managedHookDsl")?;
        let sig = extract_string_prop(ctx, opts, &["signature", "sig"], "managedHookDsl")?;
        let dsl = extract_string_prop(ctx, opts, &["dsl", "script"], "managedHookDsl")?;
        return Ok((class_name, method_name, sig, dsl));
    }

    if argc >= 4 {
        let Some(class_name) = JSValue(*argv).to_string(ctx) else {
            return Err(throw_internal_error(
                ctx,
                "managedHookDsl arg1 className must be a string",
            ));
        };
        let Some(method_name) = JSValue(*argv.add(1)).to_string(ctx) else {
            return Err(throw_internal_error(
                ctx,
                "managedHookDsl arg2 methodName must be a string",
            ));
        };
        let Some(sig) = JSValue(*argv.add(2)).to_string(ctx) else {
            return Err(throw_internal_error(
                ctx,
                "managedHookDsl arg3 signature must be a string",
            ));
        };
        let Some(dsl) = JSValue(*argv.add(3)).to_string(ctx) else {
            return Err(throw_internal_error(ctx, "managedHookDsl arg4 dsl must be a string"));
        };
        return Ok((class_name, method_name, sig, dsl));
    }

    Err(throw_internal_error(
        ctx,
        "managedHookDsl requires object or (className, methodName, signature, dsl)",
    ))
}

pub(in crate::jsapi::java) unsafe extern "C" fn js_managed_hook_dsl(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (class_name, method_name, sig, dsl) = match extract_managed_hook_dsl_args(ctx, argc, argv) {
        Ok(v) => v,
        Err(e) => return e,
    };

    match install_managed_dsl_inner(&class_name, &method_name, &sig, &dsl) {
        Ok(()) => JSValue::bool(true).raw(),
        Err(msg) => throw_internal_error(ctx, msg),
    }
}
