use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{extract_string_arg, with_registry, with_registry_mut};
use crate::jsapi::console::{output_message, output_verbose};
use crate::value::JSValue;

use super::super::callback::*;
use super::super::jni_core::*;
use super::super::release_java_hook_resources;

pub(in crate::jsapi::java) unsafe extern "C" fn js_java_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.unhook() requires 3 arguments: class, method, signature\0".as_ptr() as *const _,
        );
    }

    let class_arg = JSValue(*argv);
    let method_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));

    let class_name = match extract_string_arg(ctx, class_arg, b"Java.unhook() first argument must be a string\0") {
        Ok(value) => value,
        Err(err) => return err,
    };

    let method_name = match extract_string_arg(ctx, method_arg, b"Java.unhook() second argument must be a string\0") {
        Ok(value) => value,
        Err(err) => return err,
    };

    let sig_str = match extract_string_arg(ctx, sig_arg, b"Java.unhook() third argument must be a string\0") {
        Ok(value) => value,
        Err(err) => return err,
    };

    let actual_sig = if let Some(stripped) = sig_str.strip_prefix("static:") {
        stripped.to_string()
    } else {
        sig_str
    };

    let key = method_key(&class_name, &method_name, &actual_sig);
    let art_method_addr = with_registry(&JAVA_HOOK_REGISTRY, |registry| {
        registry.iter().find(|(_, v)| v.method_key == key).map(|(k, _)| *k)
    })
    .flatten();

    let art_method_addr = match art_method_addr {
        Some(am) => am,
        None => {
            return ffi::JS_ThrowInternalError(ctx, b"method not hooked\0".as_ptr() as *const _);
        }
    };

    let hook_data = with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| registry.remove(&art_method_addr)).flatten();

    let hook_data = match hook_data {
        Some(d) => d,
        None => {
            return ffi::JS_ThrowInternalError(ctx, b"method not hooked\0".as_ptr() as *const _);
        }
    };

    match &hook_data.hook_type {
        HookType::Replaced {
            replacement_addr,
            per_method_hook_target,
        } => {
            output_verbose(&format!(
                "[java unhook] 开始: art_method={:#x}, replacement={:#x}, per_method={:?}",
                hook_data.art_method, replacement_addr, per_method_hook_target
            ));

            delete_replacement_method(hook_data.art_method);
            output_verbose("[java unhook] Step 1: replacedMethods 已删除");

            if let Some(target) = per_method_hook_target {
                hook_ffi::hook_remove(*target as *mut std::ffi::c_void);
                // stealth2: hook_remove 只恢复 slot，还需恢复 recomp 代码页上的 B 指令
                let _ = crate::recomp::revert_slot_patch(hook_data.original_entry_point as usize);
                output_verbose(&format!("[java unhook] Step 2: Layer 3 hook 已移除: {:#x}", target));
            }

            if let Some(spec) = ART_METHOD_SPEC.get() {
                let ep_offset = spec.entry_point_offset;
                let data_off = spec.data_offset;

                std::ptr::write_volatile(
                    (hook_data.art_method as usize + spec.access_flags_offset) as *mut u32,
                    hook_data.original_access_flags,
                );
                std::ptr::write_volatile(
                    (hook_data.art_method as usize + data_off) as *mut u64,
                    hook_data.original_data,
                );
                std::ptr::write_volatile(
                    (hook_data.art_method as usize + ep_offset) as *mut u64,
                    hook_data.original_entry_point,
                );

                hook_ffi::hook_flush_cache((hook_data.art_method as usize) as *mut std::ffi::c_void, ep_offset + 8);
                output_verbose("[java unhook] Step 3: ArtMethod 字段已恢复");
            }

            hook_ffi::hook_remove_redirect(hook_data.art_method);
            output_verbose("[java unhook] Step 4: native trampoline 已移除");

            if !wait_for_in_flight_java_hook_callbacks(std::time::Duration::from_millis(200)) {
                output_verbose(&format!(
                    "[java unhook] 等待 in-flight callbacks 超时，remaining={}",
                    in_flight_java_hook_callbacks()
                ));
            }
            output_verbose(&format!(
                "[java unhook] Step 5: in-flight callbacks 已收敛，replacement={:#x}",
                replacement_addr
            ));
        }
    }

    let env_opt = get_thread_env().ok();
    release_java_hook_resources(&hook_data, env_opt, false, true);

    output_message(&format!(
        "[java unhook] 完成: {}.{}{}",
        class_name, method_name, actual_sig
    ));

    JSValue::bool(true).raw()
}
