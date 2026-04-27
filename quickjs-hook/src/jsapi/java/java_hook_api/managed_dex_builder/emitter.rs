use std::collections::{BTreeMap, BTreeSet};

use super::dex_ir::DexLabel;
use super::dsl::{
    DslCallKind, DslCallStmt, DslCondition, DslFieldStmt, DslIntBinOp, DslOrigArgs, DslProgram, DslStmt, DslTarget,
    DslUnaryOp, DslValue,
};
use super::{
    array_component_descriptor, common_value_descriptor_with_env, descriptor_is_interface, descriptor_list_word_count,
    descriptor_word_count, emit_return_from_orig, java_class_to_descriptor, java_class_to_descriptor_or_primitive,
    parse_call_params, parse_method_signature, resolve_call_proto_with_arg_types, resolve_field_with_env,
    return_is_object, value_kind_from_descriptor, DexIntBinOp, DexIntLit16Op, DexIntLit8Op, DexIrBuilder, FieldRef,
    GeneratedStringLiteral, IfCmpOp, MethodRef, ValueKind,
};
use crate::jsapi::java::jni_core::JniEnv;

pub(super) const BASE_LOCAL_REG_COUNT: u16 = 5;
const REG_RESULT: u8 = 0;
const REG_LAST_OBJECT: u8 = 1;
const REG_LOOP_LIMIT: u8 = 2;
const REG_TMP0: u8 = 3;
const REG_TMP1: u8 = 4;

pub(super) struct HelperParamLayout {
    this_reg: Option<u8>,
    this_descriptor: Option<String>,
    arg_regs: Vec<u8>,
    arg_descriptors: Vec<String>,
    local_regs: BTreeMap<String, LocalSlot>,
}

#[derive(Clone)]
pub(super) struct LocalSlot {
    reg: u8,
    descriptor: String,
}

#[derive(Clone)]
pub(super) struct DslBuildContext {
    env: JniEnv,
    generated_type: String,
    pub(super) string_literals: Vec<GeneratedStringLiteral>,
    int_expr_scratch_base: u16,
    int_expr_scratch_count: u16,
    range_scratch_base: u16,
    target_narrow_types: BTreeMap<DslTargetKey, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DslTargetKey {
    This,
    Arg(usize),
    Local(String),
}

fn dsl_target_key(target: &DslTarget) -> Option<DslTargetKey> {
    match target {
        DslTarget::This => Some(DslTargetKey::This),
        DslTarget::Arg(index) => Some(DslTargetKey::Arg(*index)),
        DslTarget::Local(name) => Some(DslTargetKey::Local(name.clone())),
        DslTarget::Last | DslTarget::Result => None,
    }
}

fn dsl_value_target_key(value: &DslValue) -> Option<DslTargetKey> {
    let DslValue::Target(target) = value else {
        return None;
    };
    dsl_target_key(target)
}

impl DslBuildContext {
    pub(super) fn new(
        env: JniEnv,
        generated_type: String,
        int_expr_scratch_base: u16,
        int_expr_scratch_count: u16,
        range_scratch_base: u16,
    ) -> Self {
        Self {
            env,
            generated_type,
            string_literals: Vec::new(),
            int_expr_scratch_base,
            int_expr_scratch_count,
            range_scratch_base,
            target_narrow_types: BTreeMap::new(),
        }
    }

    fn int_expr_scratch_reg(&self, index: u16) -> Result<u8, String> {
        if index >= self.int_expr_scratch_count {
            return Err(format!(
                "int expression requires scratch register {}, only {} reserved",
                index + 1,
                self.int_expr_scratch_count
            ));
        }
        checked_reg(self.int_expr_scratch_base + index, "int expression scratch register")
    }

    fn string_literal_field(&mut self, value: &str) -> FieldRef {
        if let Some(existing) = self.string_literals.iter().find(|lit| lit.value == value) {
            return FieldRef::new(
                self.generated_type.clone(),
                "Ljava/lang/String;".to_string(),
                existing.field_name.clone(),
            );
        }
        let field_name = format!("__rf_str{}", self.string_literals.len());
        self.string_literals.push(GeneratedStringLiteral {
            field_name: field_name.clone(),
            value: value.to_string(),
        });
        FieldRef::new(
            self.generated_type.clone(),
            "Ljava/lang/String;".to_string(),
            field_name,
        )
    }

    fn with_target_narrow_type<F>(&mut self, key: DslTargetKey, descriptor: String, f: F) -> Result<bool, String>
    where
        F: FnOnce(&mut Self) -> Result<bool, String>,
    {
        self.with_target_narrow_types(&[(key, descriptor)], f)
    }

    fn with_target_narrow_types<F, R>(&mut self, facts: &[(DslTargetKey, String)], f: F) -> Result<R, String>
    where
        F: FnOnce(&mut Self) -> Result<R, String>,
    {
        let previous = facts
            .iter()
            .map(|(key, descriptor)| {
                let old = self.target_narrow_types.insert(key.clone(), descriptor.clone());
                (key.clone(), old)
            })
            .collect::<Vec<_>>();
        let result = f(self);
        for (key, old) in previous.into_iter().rev() {
            if let Some(old) = old {
                self.target_narrow_types.insert(key, old);
            } else {
                self.target_narrow_types.remove(&key);
            }
        }
        result
    }
}

fn condition_narrow_facts_when_true(condition: &DslCondition) -> Result<Vec<(DslTargetKey, String)>, String> {
    match condition {
        DslCondition::InstanceOf { value, class_name } => {
            let Some(key) = dsl_value_target_key(value) else {
                return Ok(Vec::new());
            };
            Ok(vec![(key, java_class_to_descriptor(class_name)?)])
        }
        DslCondition::And(left, right) => {
            let mut facts = condition_narrow_facts_when_true(left)?;
            facts.extend(condition_narrow_facts_when_true(right)?);
            Ok(facts)
        }
        DslCondition::Not(condition) => condition_narrow_facts_when_false(condition),
        _ => Ok(Vec::new()),
    }
}

fn condition_narrow_facts_when_false(condition: &DslCondition) -> Result<Vec<(DslTargetKey, String)>, String> {
    match condition {
        DslCondition::Or(left, right) => {
            let mut facts = condition_narrow_facts_when_false(left)?;
            facts.extend(condition_narrow_facts_when_false(right)?);
            Ok(facts)
        }
        DslCondition::Not(condition) => condition_narrow_facts_when_true(condition),
        _ => Ok(Vec::new()),
    }
}

pub(super) fn helper_param_layout(
    is_static: bool,
    target_type: &str,
    target_params: &[String],
    local_count: u16,
    local_slots: BTreeMap<String, LocalSlot>,
) -> Result<HelperParamLayout, String> {
    let mut next = local_count;
    let this_reg = if is_static {
        None
    } else {
        let reg = checked_reg(next, "this register")?;
        next += descriptor_word_count(target_type);
        Some(reg)
    };
    let this_descriptor = if is_static { None } else { Some(target_type.to_string()) };
    let mut arg_regs = Vec::with_capacity(target_params.len());
    for param in target_params {
        let reg = checked_reg(next, "argument register")?;
        next += descriptor_word_count(param);
        arg_regs.push(reg);
    }
    Ok(HelperParamLayout {
        this_reg,
        this_descriptor,
        arg_regs,
        arg_descriptors: target_params.to_vec(),
        local_regs: local_slots,
    })
}

fn checked_reg(reg: u16, what: &str) -> Result<u8, String> {
    if reg > u8::MAX as u16 {
        return Err(format!("{} out of dex register range: v{}", what, reg));
    }
    Ok(reg as u8)
}

fn emit_copy_value(ir: &mut DexIrBuilder, dst: u8, src: u8, descriptor: &str) -> Result<(), String> {
    if dst == src {
        return Ok(());
    }
    let kind = value_kind_from_descriptor(descriptor)?;
    ir.move_from16(dst, src as u16, kind);
    Ok(())
}

fn emit_copy_object_if_needed(ir: &mut DexIrBuilder, reg: u8, temp: u8) -> u8 {
    if reg <= 0x0f {
        reg
    } else {
        ir.move_from16(temp, reg as u16, ValueKind::Object);
        temp
    }
}

fn emit_copy_field_value_if_needed(ir: &mut DexIrBuilder, reg: u8, temp: u8, kind: ValueKind) -> u8 {
    if reg <= 0x0f {
        reg
    } else {
        ir.move_from16(temp, reg as u16, kind);
        temp
    }
}

fn emit_new_object(
    ir: &mut DexIrBuilder,
    class_name: &str,
    ctor_sig: Option<&str>,
    args: &[DslValue],
    sink: &FieldRef,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<MethodRef, String> {
    let new_type = java_class_to_descriptor(class_name)?;
    let (params, return_type) = if let Some(sig) = ctor_sig {
        parse_method_signature(sig)?
    } else {
        (Vec::new(), "V".to_string())
    };
    if return_type != "V" {
        return Err(format!("constructor signature must return void, got '{}'", return_type));
    }
    if params.len() != args.len() {
        return Err(format!(
            "{}.<init>{} expects {} explicit args, got {}",
            class_name,
            ctor_sig.unwrap_or("()V"),
            params.len(),
            args.len()
        ));
    }
    let ctor = MethodRef::new(new_type.clone(), "<init>", "V", params.clone());
    ir.new_instance(REG_LAST_OBJECT, new_type);
    emit_invoke_with_values(
        ir,
        ManagedInvokeKind::Direct,
        ctor.clone(),
        Some((REG_LAST_OBJECT, "Ljava/lang/Object;")),
        &params,
        args,
        layout,
        dsl_ctx,
    )?;
    ir.sput_object(REG_LAST_OBJECT, sink.clone());
    Ok(ctor)
}

fn emit_new_object_value(
    ir: &mut DexIrBuilder,
    class_name: &str,
    ctor_sig: Option<&str>,
    args: &[DslValue],
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let new_type = java_class_to_descriptor(class_name)?;
    if !value_descriptor_assignable_to(&new_type, expected_type) {
        return Err(format!(
            "new expression type {} cannot be passed as {}",
            new_type, expected_type
        ));
    }
    let (params, return_type) = if let Some(sig) = ctor_sig {
        parse_method_signature(sig)?
    } else {
        (Vec::new(), "V".to_string())
    };
    if return_type != "V" {
        return Err(format!("constructor signature must return void, got '{}'", return_type));
    }
    if params.len() != args.len() {
        return Err(format!(
            "{}.<init>{} expects {} explicit args, got {}",
            class_name,
            ctor_sig.unwrap_or("()V"),
            params.len(),
            args.len()
        ));
    }
    let ctor = MethodRef::new(new_type.clone(), "<init>", "V", params.clone());
    ir.new_instance(dst, new_type);
    emit_invoke_with_values(
        ir,
        ManagedInvokeKind::Direct,
        ctor,
        Some((dst, "Ljava/lang/Object;")),
        &params,
        args,
        layout,
        dsl_ctx,
    )?;
    Ok(dst)
}

fn emit_discard_result(ir: &mut DexIrBuilder, return_type: &str) -> Result<(), String> {
    match return_type {
        "V" => {}
        "J" | "D" => ir.move_result_wide(REG_RESULT),
        ret if return_is_object(ret) => ir.move_result_object(REG_LAST_OBJECT),
        "Z" | "B" | "C" | "S" | "I" | "F" => ir.move_result(REG_RESULT),
        other => return Err(format!("unsupported call return type '{}'", other)),
    }
    Ok(())
}

fn emit_move_result_value(ir: &mut DexIrBuilder, return_type: &str, dst: u8) -> Result<u8, String> {
    match return_type {
        "V" => Err("void call cannot be used as a value".to_string()),
        "J" | "D" => {
            ir.move_result_wide(dst);
            Ok(dst)
        }
        ret if return_is_object(ret) => {
            ir.move_result_object(dst);
            Ok(dst)
        }
        "Z" | "B" | "C" | "S" | "I" | "F" => {
            ir.move_result(dst);
            Ok(dst)
        }
        other => Err(format!("unsupported call return type '{}'", other)),
    }
}

fn emit_call_value(
    ir: &mut DexIrBuilder,
    stmt: &DslCallStmt,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let class_type = resolve_member_class_type(
        stmt.class_name.as_deref(),
        stmt.target.as_ref(),
        stmt.receiver.as_deref(),
        layout,
        dsl_ctx,
    )?;
    let arg_types = infer_call_arg_descriptors(stmt, layout, dsl_ctx)?;
    let (params, return_type, full_sig) =
        resolve_call_proto_with_arg_types(dsl_ctx.env, stmt, &class_type, Some(&arg_types))?;
    if return_type == "V" {
        return Err(format!(
            "{}.{}{} returns void and cannot be used as a value",
            stmt.class_label(),
            stmt.method_name,
            full_sig
        ));
    }
    if !value_descriptor_assignable_to(&return_type, expected_type) {
        return Err(format!(
            "call expression return type {} cannot be passed as {}",
            return_type, expected_type
        ));
    }
    if params.len() != stmt.args.len() {
        return Err(format!(
            "{}.{}{} expects {} explicit args, got {}",
            stmt.class_label(),
            stmt.method_name,
            full_sig,
            params.len(),
            stmt.args.len()
        ));
    }
    let method = MethodRef::new(
        class_type.clone(),
        stmt.method_name.clone(),
        return_type.clone(),
        params.clone(),
    );
    let receiver = emit_call_receiver(ir, stmt, &class_type, layout, dsl_ctx)?;
    let invoke_kind = resolve_managed_invoke_kind(dsl_ctx.env, stmt.kind, &class_type);
    if stmt.null_safe {
        return emit_null_safe_call_value(
            ir,
            invoke_kind,
            method,
            receiver,
            &params,
            &stmt.args,
            &return_type,
            dst,
            layout,
            dsl_ctx,
        );
    }
    emit_invoke_with_values(ir, invoke_kind, method, receiver, &params, &stmt.args, layout, dsl_ctx)?;
    emit_move_result_value(ir, &return_type, dst)
}

fn emit_null_safe_default(ir: &mut DexIrBuilder, return_type: &str, dst: u8) -> Result<(), String> {
    match return_type {
        "V" => Err("void null-safe call cannot be used as a value".to_string()),
        "J" | "D" => Err("wide null-safe call result is not supported yet".to_string()),
        ret if return_is_object(ret) => {
            ir.const4(dst, 0);
            Ok(())
        }
        "Z" | "B" | "C" | "S" | "I" | "F" => {
            ir.const4(dst, 0);
            Ok(())
        }
        other => Err(format!("unsupported null-safe call return type '{}'", other)),
    }
}

fn emit_null_safe_call_value(
    ir: &mut DexIrBuilder,
    invoke_kind: ManagedInvokeKind,
    method: MethodRef,
    receiver: Option<(u8, &str)>,
    params: &[String],
    args: &[DslValue],
    return_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let Some((receiver_reg, receiver_desc)) = receiver else {
        return Err("null-safe call requires a receiver".to_string());
    };
    if matches!(invoke_kind, ManagedInvokeKind::Static) {
        return Err("null-safe call is only valid for instance/interface methods".to_string());
    }
    let null_label = ir.new_label();
    let done_label = ir.new_label();
    ir.if_eqz(receiver_reg, null_label);
    emit_invoke_with_values(
        ir,
        invoke_kind,
        method,
        Some((receiver_reg, receiver_desc)),
        params,
        args,
        layout,
        dsl_ctx,
    )?;
    emit_move_result_value(ir, return_type, dst)?;
    ir.goto16(done_label);
    ir.bind(null_label)?;
    emit_null_safe_default(ir, return_type, dst)?;
    ir.bind(done_label)?;
    Ok(dst)
}

fn emit_field_get_value(
    ir: &mut DexIrBuilder,
    stmt: &DslFieldStmt,
    is_static: bool,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let class_type = resolve_member_class_type(
        stmt.class_name.as_deref(),
        stmt.target.as_ref(),
        stmt.receiver.as_deref(),
        layout,
        dsl_ctx,
    )?;
    let (declaring_type, field_type) = resolve_field_ref_parts(dsl_ctx.env, stmt, is_static, &class_type)?;
    if !value_descriptor_assignable_to(&field_type, expected_type) {
        return Err(format!(
            "field expression type {} cannot be passed as {}",
            field_type, expected_type
        ));
    }
    let field = FieldRef::new(declaring_type, field_type.clone(), stmt.field_name.clone());
    let kind = value_kind_from_descriptor(&field_type)?;
    if is_static {
        ir.sget(dst, field, kind);
    } else {
        let obj = emit_field_receiver(ir, stmt, layout, dsl_ctx)?;
        ir.iget(dst, obj, field, kind);
    }
    Ok(dst)
}

fn emit_cast_value(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    class_name: &str,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let ty = java_class_to_descriptor(class_name)?;
    if !return_is_object(expected_type) {
        return Err(format!("cast expression cannot be passed as {}", expected_type));
    }
    let src = emit_load_value(ir, value, "Ljava/lang/Object;", dst, layout, dsl_ctx)?;
    let reg = emit_copy_object_if_needed(ir, src, dst);
    ir.check_cast(reg, ty);
    if reg != dst {
        ir.move_from16(dst, reg as u16, ValueKind::Object);
    }
    Ok(dst)
}

fn emit_load_value(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    expected_type: &str,
    temp_reg: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    match value {
        DslValue::Target(target) => resolve_target_reg(target, layout),
        DslValue::String(value) => {
            if !return_is_object(expected_type) {
                return Err(format!("string literal cannot be passed as {}", expected_type));
            }
            let field = dsl_ctx.string_literal_field(value);
            ir.sget(temp_reg, field, ValueKind::Object);
            Ok(temp_reg)
        }
        DslValue::Int(value) => {
            if matches!(expected_type, "J" | "D") {
                return Err("wide integer literals are not supported in managed DSL yet".to_string());
            }
            ir.const16(temp_reg, *value);
            Ok(temp_reg)
        }
        DslValue::Bool(value) => {
            if expected_type != "Z" {
                return Err(format!("boolean literal cannot be passed as {}", expected_type));
            }
            ir.const4(temp_reg, if *value { 1 } else { 0 });
            Ok(temp_reg)
        }
        DslValue::Null => {
            if !return_is_object(expected_type) {
                return Err(format!("null cannot be passed as {}", expected_type));
            }
            ir.const4(temp_reg, 0);
            Ok(temp_reg)
        }
        DslValue::UnaryOp { op, value } => emit_unary_value(ir, *op, value, expected_type, temp_reg, layout, dsl_ctx),
        DslValue::IntBinOp { op, left, right } => {
            if expected_type != "I" {
                return Err(format!("int expression cannot be passed as {}", expected_type));
            }
            emit_int_binop_value(ir, *op, left, right, temp_reg, layout, dsl_ctx)
        }
        DslValue::Ternary {
            condition,
            then_value,
            else_value,
        } => emit_ternary_value(
            ir,
            condition,
            then_value,
            else_value,
            expected_type,
            temp_reg,
            layout,
            dsl_ctx,
        ),
        DslValue::Call(stmt) => emit_call_value(ir, stmt, expected_type, temp_reg, layout, dsl_ctx),
        DslValue::NewObject {
            class_name,
            ctor_sig,
            args,
        } => emit_new_object_value(
            ir,
            class_name,
            ctor_sig.as_deref(),
            args,
            expected_type,
            temp_reg,
            layout,
            dsl_ctx,
        ),
        DslValue::FieldGet { stmt, is_static } => {
            emit_field_get_value(ir, stmt, *is_static, expected_type, temp_reg, layout, dsl_ctx)
        }
        DslValue::Cast { value, class_name } => {
            emit_cast_value(ir, value, class_name, expected_type, temp_reg, layout, dsl_ctx)
        }
        DslValue::ArrayLength(array) => {
            if expected_type != "I" {
                return Err(format!("arrayLength expression cannot be passed as {}", expected_type));
            }
            emit_array_length_value(ir, array, temp_reg, layout, dsl_ctx)
        }
        DslValue::ArrayGet {
            array,
            index,
            type_name,
        } => {
            let component_type = resolve_array_component_type(array, type_name.as_deref(), layout, dsl_ctx)?;
            if !value_descriptor_assignable_to(&component_type, expected_type) {
                return Err(format!(
                    "aget expression type {} cannot be passed as {}",
                    component_type, expected_type
                ));
            }
            emit_array_get_value(ir, array, index, &component_type, temp_reg, layout, dsl_ctx)
        }
    }
}

fn value_descriptor_assignable_to(src: &str, dst: &str) -> bool {
    src == dst || (return_is_object(src) && return_is_object(dst))
}

fn emit_ternary_value(
    ir: &mut DexIrBuilder,
    condition: &DslCondition,
    then_value: &DslValue,
    else_value: &DslValue,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    if matches!(expected_type, "J" | "D") {
        return Err("wide ternary result is not supported yet".to_string());
    }
    if expected_type == "V" {
        return Err("void ternary result is not supported".to_string());
    }
    let then_label = ir.new_label();
    let else_label = ir.new_label();
    let done_label = ir.new_label();
    emit_condition_branch(ir, condition, then_label, else_label, layout, dsl_ctx)?;
    ir.bind(then_label)?;
    let then_facts = condition_narrow_facts_when_true(condition)?;
    let then_reg = dsl_ctx.with_target_narrow_types(&then_facts, |dsl_ctx| {
        emit_load_value(ir, then_value, expected_type, dst, layout, dsl_ctx)
    })?;
    emit_copy_value(ir, dst, then_reg, expected_type)?;
    ir.goto16(done_label);
    ir.bind(else_label)?;
    let else_facts = condition_narrow_facts_when_false(condition)?;
    let else_reg = dsl_ctx.with_target_narrow_types(&else_facts, |dsl_ctx| {
        emit_load_value(ir, else_value, expected_type, dst, layout, dsl_ctx)
    })?;
    emit_copy_value(ir, dst, else_reg, expected_type)?;
    ir.bind(done_label)?;
    Ok(dst)
}

fn emit_condition_branch(
    ir: &mut DexIrBuilder,
    condition: &DslCondition,
    true_label: DexLabel,
    false_label: DexLabel,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    match condition {
        DslCondition::Const(true) => ir.goto16(true_label),
        DslCondition::Const(false) => ir.goto16(false_label),
        DslCondition::Bool { value } => {
            let reg = emit_load_cmp_value(ir, value, "Z", REG_TMP0, layout, dsl_ctx)?;
            ir.if_eqz(reg, false_label);
            ir.goto16(true_label);
        }
        DslCondition::Null { value, invert } => {
            let reg = emit_load_value(ir, value, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
            let obj = emit_copy_object_if_needed(ir, reg, REG_TMP1);
            if *invert {
                ir.if_eqz(obj, false_label);
                ir.goto16(true_label);
            } else {
                ir.if_eqz(obj, true_label);
                ir.goto16(false_label);
            }
        }
        DslCondition::Cmp { op, left, right } => {
            let expected_type = cmp_expected_type(left, right, layout, dsl_ctx)?;
            let left_reg = emit_load_cmp_value(ir, left, expected_type, REG_TMP0, layout, dsl_ctx)?;
            let right_reg = emit_load_cmp_value(ir, right, expected_type, REG_TMP1, layout, dsl_ctx)?;
            ir.if_cmp(*op, left_reg, right_reg, true_label);
            ir.goto16(false_label);
        }
        DslCondition::InstanceOf { value, class_name } => {
            let ty = java_class_to_descriptor(class_name)?;
            let src = emit_load_value(ir, value, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
            let obj = emit_copy_object_if_needed(ir, src, REG_TMP1);
            ir.instance_of(REG_TMP0, obj, ty);
            ir.if_eqz(REG_TMP0, false_label);
            ir.goto16(true_label);
        }
        DslCondition::And(left, right) => {
            let right_label = ir.new_label();
            emit_condition_branch(ir, left, right_label, false_label, layout, dsl_ctx)?;
            ir.bind(right_label)?;
            let facts = condition_narrow_facts_when_true(left)?;
            dsl_ctx.with_target_narrow_types(&facts, |dsl_ctx| {
                emit_condition_branch(ir, right, true_label, false_label, layout, dsl_ctx)
            })?;
        }
        DslCondition::Or(left, right) => {
            let right_label = ir.new_label();
            emit_condition_branch(ir, left, true_label, right_label, layout, dsl_ctx)?;
            ir.bind(right_label)?;
            let facts = condition_narrow_facts_when_false(left)?;
            dsl_ctx.with_target_narrow_types(&facts, |dsl_ctx| {
                emit_condition_branch(ir, right, true_label, false_label, layout, dsl_ctx)
            })?;
        }
        DslCondition::Not(condition) => {
            emit_condition_branch(ir, condition, false_label, true_label, layout, dsl_ctx)?;
        }
    }
    Ok(())
}

fn dex_int_binop(op: DslIntBinOp) -> DexIntBinOp {
    match op {
        DslIntBinOp::Add => DexIntBinOp::Add,
        DslIntBinOp::Sub => DexIntBinOp::Sub,
        DslIntBinOp::Mul => DexIntBinOp::Mul,
        DslIntBinOp::Div => DexIntBinOp::Div,
        DslIntBinOp::Rem => DexIntBinOp::Rem,
        DslIntBinOp::And => DexIntBinOp::And,
        DslIntBinOp::Or => DexIntBinOp::Or,
        DslIntBinOp::Xor => DexIntBinOp::Xor,
        DslIntBinOp::Shl => DexIntBinOp::Shl,
        DslIntBinOp::Shr => DexIntBinOp::Shr,
        DslIntBinOp::Ushr => DexIntBinOp::Ushr,
    }
}

fn emit_unary_value(
    ir: &mut DexIrBuilder,
    op: DslUnaryOp,
    value: &DslValue,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    emit_unary_value_with_scratch(ir, op, value, expected_type, dst, 0, layout, dsl_ctx)
}

fn emit_unary_value_with_scratch(
    ir: &mut DexIrBuilder,
    op: DslUnaryOp,
    value: &DslValue,
    expected_type: &str,
    dst: u8,
    scratch_index: u16,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    match op {
        DslUnaryOp::Neg => {
            if expected_type != "I" {
                return Err(format!("int unary expression cannot be passed as {}", expected_type));
            }
            let src = emit_int_expr_value(ir, value, dst, scratch_index, layout, dsl_ctx)?;
            if src != dst {
                ir.move_from16(dst, src as u16, ValueKind::Narrow);
            }
            ir.int_binop_lit8(DexIntLit8Op::Rsub, dst, dst, 0);
            Ok(dst)
        }
        DslUnaryOp::BitNot => {
            if expected_type != "I" {
                return Err(format!("int unary expression cannot be passed as {}", expected_type));
            }
            let src = emit_int_expr_value(ir, value, dst, scratch_index, layout, dsl_ctx)?;
            if src != dst {
                ir.move_from16(dst, src as u16, ValueKind::Narrow);
            }
            ir.int_binop_lit8(DexIntLit8Op::Xor, dst, dst, -1);
            Ok(dst)
        }
        DslUnaryOp::BoolNot => {
            if expected_type != "Z" {
                return Err(format!(
                    "boolean unary expression cannot be passed as {}",
                    expected_type
                ));
            }
            let src = emit_load_value(ir, value, "Z", dst, layout, dsl_ctx)?;
            if src != dst {
                ir.move_from16(dst, src as u16, ValueKind::Narrow);
            }
            ir.int_binop_lit8(DexIntLit8Op::Xor, dst, dst, 1);
            Ok(dst)
        }
    }
}

fn emit_int_binop_value(
    ir: &mut DexIrBuilder,
    op: DslIntBinOp,
    left: &DslValue,
    right: &DslValue,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    emit_int_binop_expr(ir, op, left, right, dst, 0, layout, dsl_ctx)
}

fn emit_int_expr_value(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    dst: u8,
    scratch_index: u16,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    match value {
        DslValue::IntBinOp { op, left, right } => {
            emit_int_binop_expr(ir, *op, left, right, dst, scratch_index, layout, dsl_ctx)
        }
        DslValue::UnaryOp {
            op: op @ (DslUnaryOp::Neg | DslUnaryOp::BitNot),
            value,
        } => emit_unary_value_with_scratch(ir, *op, value, "I", dst, scratch_index, layout, dsl_ctx),
        _ => emit_load_value(ir, value, "I", dst, layout, dsl_ctx),
    }
}

fn emit_int_binop_expr(
    ir: &mut DexIrBuilder,
    op: DslIntBinOp,
    left: &DslValue,
    right: &DslValue,
    dst: u8,
    scratch_index: u16,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    if let Some((lit_op, literal)) = right_lit8_op(op, right) {
        let src = emit_int_expr_value(ir, left, dst, scratch_index, layout, dsl_ctx)?;
        if src != dst {
            ir.move_from16(dst, src as u16, ValueKind::Narrow);
        }
        ir.int_binop_lit8(lit_op, dst, dst, literal);
        return Ok(dst);
    }
    if dst <= 0x0f {
        if let Some((lit_op, literal)) = right_lit16_op(op, right) {
            let src = emit_int_expr_value(ir, left, dst, scratch_index, layout, dsl_ctx)?;
            if src != dst {
                ir.move_from16(dst, src as u16, ValueKind::Narrow);
            }
            ir.int_binop_lit16(lit_op, dst, dst, literal);
            return Ok(dst);
        }
    }
    if let Some((lit_op, literal)) = left_lit8_op(op, left) {
        let src = emit_int_expr_value(ir, right, dst, scratch_index, layout, dsl_ctx)?;
        if src != dst {
            ir.move_from16(dst, src as u16, ValueKind::Narrow);
        }
        ir.int_binop_lit8(lit_op, dst, dst, literal);
        return Ok(dst);
    }
    if dst <= 0x0f {
        if let Some((lit_op, literal)) = left_lit16_op(op, left) {
            let src = emit_int_expr_value(ir, right, dst, scratch_index, layout, dsl_ctx)?;
            if src != dst {
                ir.move_from16(dst, src as u16, ValueKind::Narrow);
            }
            ir.int_binop_lit16(lit_op, dst, dst, literal);
            return Ok(dst);
        }
    }
    let left_dst = dsl_ctx.int_expr_scratch_reg(scratch_index)?;
    let left_reg = emit_int_expr_value(ir, left, left_dst, scratch_index, layout, dsl_ctx)?;
    if left_reg != left_dst {
        ir.move_from16(left_dst, left_reg as u16, ValueKind::Narrow);
    }
    let right_index = scratch_index
        .checked_add(1)
        .ok_or_else(|| "too many int expression scratch registers".to_string())?;
    let right_dst = dsl_ctx.int_expr_scratch_reg(right_index)?;
    let right_reg = emit_int_expr_value(ir, right, right_dst, right_index, layout, dsl_ctx)?;
    if right_reg != right_dst {
        ir.move_from16(right_dst, right_reg as u16, ValueKind::Narrow);
    }
    ir.int_binop(dex_int_binop(op), dst, left_dst, right_dst);
    Ok(dst)
}

fn right_lit8_op(op: DslIntBinOp, right: &DslValue) -> Option<(DexIntLit8Op, i8)> {
    let literal = value_i8_literal(right)?;
    let lit_op = match op {
        DslIntBinOp::Add => DexIntLit8Op::Add,
        DslIntBinOp::Sub => return literal.checked_neg().map(|negated| (DexIntLit8Op::Add, negated)),
        DslIntBinOp::Mul => DexIntLit8Op::Mul,
        DslIntBinOp::Div => DexIntLit8Op::Div,
        DslIntBinOp::Rem => DexIntLit8Op::Rem,
        DslIntBinOp::And => DexIntLit8Op::And,
        DslIntBinOp::Or => DexIntLit8Op::Or,
        DslIntBinOp::Xor => DexIntLit8Op::Xor,
        DslIntBinOp::Shl => DexIntLit8Op::Shl,
        DslIntBinOp::Shr => DexIntLit8Op::Shr,
        DslIntBinOp::Ushr => DexIntLit8Op::Ushr,
    };
    Some((lit_op, literal))
}

fn right_lit16_op(op: DslIntBinOp, right: &DslValue) -> Option<(DexIntLit16Op, i16)> {
    let literal = value_i16_literal(right)?;
    let lit_op = match op {
        DslIntBinOp::Add => DexIntLit16Op::Add,
        DslIntBinOp::Sub => return literal.checked_neg().map(|negated| (DexIntLit16Op::Add, negated)),
        DslIntBinOp::Mul => DexIntLit16Op::Mul,
        DslIntBinOp::Div => DexIntLit16Op::Div,
        DslIntBinOp::Rem => DexIntLit16Op::Rem,
        DslIntBinOp::And => DexIntLit16Op::And,
        DslIntBinOp::Or => DexIntLit16Op::Or,
        DslIntBinOp::Xor => DexIntLit16Op::Xor,
        DslIntBinOp::Shl | DslIntBinOp::Shr | DslIntBinOp::Ushr => return None,
    };
    Some((lit_op, literal))
}

fn left_lit8_op(op: DslIntBinOp, left: &DslValue) -> Option<(DexIntLit8Op, i8)> {
    let literal = value_i8_literal(left)?;
    let lit_op = match op {
        DslIntBinOp::Add => DexIntLit8Op::Add,
        DslIntBinOp::Sub => DexIntLit8Op::Rsub,
        DslIntBinOp::Mul => DexIntLit8Op::Mul,
        DslIntBinOp::And => DexIntLit8Op::And,
        DslIntBinOp::Or => DexIntLit8Op::Or,
        DslIntBinOp::Xor => DexIntLit8Op::Xor,
        DslIntBinOp::Div | DslIntBinOp::Rem | DslIntBinOp::Shl | DslIntBinOp::Shr | DslIntBinOp::Ushr => return None,
    };
    Some((lit_op, literal))
}

fn left_lit16_op(op: DslIntBinOp, left: &DslValue) -> Option<(DexIntLit16Op, i16)> {
    let literal = value_i16_literal(left)?;
    let lit_op = match op {
        DslIntBinOp::Add => DexIntLit16Op::Add,
        DslIntBinOp::Sub => DexIntLit16Op::Rsub,
        DslIntBinOp::Mul => DexIntLit16Op::Mul,
        DslIntBinOp::And => DexIntLit16Op::And,
        DslIntBinOp::Or => DexIntLit16Op::Or,
        DslIntBinOp::Xor => DexIntLit16Op::Xor,
        DslIntBinOp::Div | DslIntBinOp::Rem | DslIntBinOp::Shl | DslIntBinOp::Shr | DslIntBinOp::Ushr => return None,
    };
    Some((lit_op, literal))
}

fn value_i8_literal(value: &DslValue) -> Option<i8> {
    let DslValue::Int(value) = value else {
        return None;
    };
    (*value).try_into().ok()
}

fn value_i16_literal(value: &DslValue) -> Option<i16> {
    let DslValue::Int(value) = value else {
        return None;
    };
    Some(*value)
}

fn infer_value_descriptor(
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<Option<String>, String> {
    match value {
        DslValue::Target(target) => resolve_target_descriptor(target, layout, dsl_ctx).map(Some),
        DslValue::String(_) => Ok(Some("Ljava/lang/String;".to_string())),
        DslValue::Int(_) | DslValue::IntBinOp { .. } | DslValue::ArrayLength(_) => Ok(Some("I".to_string())),
        DslValue::UnaryOp { op, .. } => match op {
            DslUnaryOp::Neg | DslUnaryOp::BitNot => Ok(Some("I".to_string())),
            DslUnaryOp::BoolNot => Ok(Some("Z".to_string())),
        },
        DslValue::Bool(_) => Ok(Some("Z".to_string())),
        DslValue::Ternary {
            condition,
            then_value,
            else_value,
        } => {
            let then_facts = condition_narrow_facts_when_true(condition)?;
            let mut then_ctx = dsl_ctx.clone();
            let then_desc = then_ctx.with_target_narrow_types(&then_facts, |dsl_ctx| {
                infer_value_descriptor(then_value, layout, dsl_ctx)
            })?;
            let else_facts = condition_narrow_facts_when_false(condition)?;
            let mut else_ctx = dsl_ctx.clone();
            let else_desc = else_ctx.with_target_narrow_types(&else_facts, |dsl_ctx| {
                infer_value_descriptor(else_value, layout, dsl_ctx)
            })?;
            common_value_descriptor_with_env(then_desc, else_desc, dsl_ctx.env)
        }
        DslValue::Null => Ok(None),
        DslValue::Call(stmt) => {
            if let Ok((_, return_type)) = parse_method_signature(&stmt.sig) {
                if return_type == "V" {
                    Ok(None)
                } else {
                    Ok(Some(return_type))
                }
            } else {
                let class_type = resolve_member_class_type(
                    stmt.class_name.as_deref(),
                    stmt.target.as_ref(),
                    stmt.receiver.as_deref(),
                    layout,
                    dsl_ctx,
                )?;
                let arg_types = infer_call_arg_descriptors(stmt, layout, dsl_ctx)?;
                let (_, return_type, _) =
                    resolve_call_proto_with_arg_types(dsl_ctx.env, stmt, &class_type, Some(&arg_types))?;
                if return_type == "V" {
                    Ok(None)
                } else {
                    Ok(Some(return_type))
                }
            }
        }
        DslValue::NewObject { class_name, .. } => java_class_to_descriptor(class_name).map(Some),
        DslValue::FieldGet { stmt, is_static } => {
            let class_type = resolve_member_class_type(
                stmt.class_name.as_deref(),
                stmt.target.as_ref(),
                stmt.receiver.as_deref(),
                layout,
                dsl_ctx,
            )?;
            resolve_field_type(dsl_ctx.env, stmt, *is_static, &class_type).map(Some)
        }
        DslValue::Cast { class_name, .. } => java_class_to_descriptor(class_name).map(Some),
        DslValue::ArrayGet { type_name, .. } => match type_name {
            Some(type_name) => java_class_to_descriptor_or_primitive(type_name).map(Some),
            None => Ok(None),
        },
    }
}

fn resolve_array_component_type(
    array: &DslValue,
    explicit_type_name: Option<&str>,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<String, String> {
    if let Some(type_name) = explicit_type_name {
        return java_class_to_descriptor_or_primitive(type_name);
    }
    let Some(array_desc) = infer_value_descriptor(array, layout, dsl_ctx)? else {
        return Err("array element type cannot be inferred; use arr[index: Type]".to_string());
    };
    array_component_descriptor(&array_desc)
}

fn emit_array_length_value(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let array_reg = emit_load_value(ir, array, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
    let array_reg = emit_copy_object_if_needed(ir, array_reg, REG_TMP1);
    let dst = if dst <= 0x0f { dst } else { REG_TMP0 };
    ir.array_length(dst, array_reg);
    Ok(dst)
}

fn emit_array_get_value(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    index: &DslValue,
    component_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let array_reg = emit_load_value(ir, array, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
    let array_reg = emit_copy_object_if_needed(ir, array_reg, REG_TMP1);
    let index_reg = emit_load_value(ir, index, "I", REG_TMP0, layout, dsl_ctx)?;
    let index_reg = emit_copy_field_value_if_needed(ir, index_reg, REG_TMP0, ValueKind::Narrow);
    let kind = value_kind_from_descriptor(component_type)?;
    ir.aget(dst, array_reg, index_reg, kind);
    Ok(dst)
}

fn resolve_target_reg(target: &DslTarget, layout: &HelperParamLayout) -> Result<u8, String> {
    match target {
        DslTarget::This => layout
            .this_reg
            .ok_or_else(|| "static target has no this register".to_string()),
        DslTarget::Arg(index) => layout
            .arg_regs
            .get(*index)
            .copied()
            .ok_or_else(|| format!("argument {} does not exist", index)),
        DslTarget::Last => Ok(REG_LAST_OBJECT),
        DslTarget::Result => Ok(REG_RESULT),
        DslTarget::Local(name) => layout
            .local_regs
            .get(name)
            .map(|slot| slot.reg)
            .ok_or_else(|| format!("local '{}' is not declared", name)),
    }
}

fn resolve_target_descriptor(
    target: &DslTarget,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<String, String> {
    if let Some(key) = dsl_target_key(target) {
        if let Some(descriptor) = dsl_ctx.target_narrow_types.get(&key) {
            return Ok(descriptor.clone());
        }
    }
    match target {
        DslTarget::This => layout
            .this_descriptor
            .clone()
            .ok_or_else(|| "static target has no this descriptor".to_string()),
        DslTarget::Arg(index) => layout
            .arg_descriptors
            .get(*index)
            .cloned()
            .ok_or_else(|| format!("argument {} does not exist", index)),
        DslTarget::Local(name) => layout
            .local_regs
            .get(name)
            .map(|slot| slot.descriptor.clone())
            .ok_or_else(|| format!("local '{}' is not declared", name)),
        DslTarget::Last | DslTarget::Result => {
            Err("target class cannot be inferred for last/result; pass the class name explicitly".to_string())
        }
    }
}

fn resolve_member_class_type(
    explicit_class_name: Option<&str>,
    target: Option<&DslTarget>,
    receiver: Option<&DslValue>,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<String, String> {
    if let Some(class_name) = explicit_class_name {
        return java_class_to_descriptor(class_name);
    }
    if let Some(receiver) = receiver {
        let Some(desc) = infer_value_descriptor(receiver, layout, dsl_ctx)? else {
            return Err("receiver class cannot be inferred from null/void expression".to_string());
        };
        if !desc.starts_with('L') || !desc.ends_with(';') {
            return Err(format!(
                "receiver class can only be inferred from object expressions, got {}",
                desc
            ));
        }
        return Ok(desc);
    }
    let Some(target) = target else {
        return Err("static member access requires an explicit class name".to_string());
    };
    let desc = resolve_target_descriptor(target, layout, dsl_ctx)?;
    if !desc.starts_with('L') || !desc.ends_with(';') {
        return Err(format!(
            "target class can only be inferred from object locals/args, got {}",
            desc
        ));
    }
    Ok(desc)
}

fn emit_call_receiver<'a>(
    ir: &mut DexIrBuilder,
    stmt: &DslCallStmt,
    class_type: &'a str,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<Option<(u8, &'a str)>, String> {
    if stmt.kind == DslCallKind::Static {
        return Ok(None);
    }
    if stmt.target.is_some() && stmt.receiver.is_some() {
        return Err("method call cannot use both target and receiver expression".to_string());
    }
    if let Some(target) = stmt.target.as_ref() {
        return resolve_target_reg(target, layout).map(|reg| Some((reg, class_type)));
    }
    if let Some(receiver) = stmt.receiver.as_ref() {
        let reg = emit_load_value(ir, receiver, "Ljava/lang/Object;", REG_LAST_OBJECT, layout, dsl_ctx)?;
        return Ok(Some((reg, class_type)));
    }
    Err("instance method call requires a target or receiver expression".to_string())
}

fn emit_field_receiver(
    ir: &mut DexIrBuilder,
    stmt: &DslFieldStmt,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    if stmt.target.is_some() && stmt.receiver.is_some() {
        return Err("field access cannot use both target and receiver expression".to_string());
    }
    if let Some(target) = stmt.target.as_ref() {
        return Ok(emit_copy_object_if_needed(
            ir,
            resolve_target_reg(target, layout)?,
            REG_TMP1,
        ));
    }
    if let Some(receiver) = stmt.receiver.as_ref() {
        let reg = emit_load_value(ir, receiver, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
        return Ok(emit_copy_object_if_needed(ir, reg, REG_TMP1));
    }
    Err("instance field access requires a target or receiver expression".to_string())
}

fn emit_field_read(
    ir: &mut DexIrBuilder,
    stmt: &DslFieldStmt,
    layout: &HelperParamLayout,
    is_static: bool,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let class_type = resolve_member_class_type(
        stmt.class_name.as_deref(),
        stmt.target.as_ref(),
        stmt.receiver.as_deref(),
        layout,
        dsl_ctx,
    )?;
    let (declaring_type, field_type) = resolve_field_ref_parts(dsl_ctx.env, stmt, is_static, &class_type)?;
    let field = FieldRef::new(declaring_type, field_type.clone(), stmt.field_name.clone());
    let kind = value_kind_from_descriptor(&field_type)?;
    let dst = if matches!(kind, ValueKind::Object) {
        REG_LAST_OBJECT
    } else {
        REG_RESULT
    };
    if is_static {
        ir.sget(dst, field, kind);
    } else {
        let obj = emit_field_receiver(ir, stmt, layout, dsl_ctx)?;
        ir.iget(dst, obj, field, kind);
    }
    Ok(())
}

fn emit_field_write(
    ir: &mut DexIrBuilder,
    stmt: &DslFieldStmt,
    layout: &HelperParamLayout,
    is_static: bool,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let class_type = resolve_member_class_type(
        stmt.class_name.as_deref(),
        stmt.target.as_ref(),
        stmt.receiver.as_deref(),
        layout,
        dsl_ctx,
    )?;
    let (declaring_type, field_type) = resolve_field_ref_parts(dsl_ctx.env, stmt, is_static, &class_type)?;
    let field = FieldRef::new(declaring_type, field_type.clone(), stmt.field_name.clone());
    let kind = value_kind_from_descriptor(&field_type)?;
    let Some(value) = &stmt.value else {
        return Err("field write requires a value".to_string());
    };
    let raw_src = emit_load_value(ir, value, &field_type, REG_TMP0, layout, dsl_ctx)?;
    let src = emit_copy_field_value_if_needed(ir, raw_src, REG_TMP0, kind);
    if is_static {
        ir.sput(src, field, kind);
    } else {
        let obj = emit_field_receiver(ir, stmt, layout, dsl_ctx)?;
        ir.iput(src, obj, field, kind);
    }
    Ok(())
}

fn resolve_field_type(env: JniEnv, stmt: &DslFieldStmt, is_static: bool, class_type: &str) -> Result<String, String> {
    if !stmt.type_name.is_empty() {
        return java_class_to_descriptor_or_primitive(&stmt.type_name);
    }
    resolve_field_with_env(env, class_type, &stmt.field_name, Some(is_static)).map(|field| field.field_type)
}

fn resolve_field_ref_parts(
    env: JniEnv,
    stmt: &DslFieldStmt,
    is_static: bool,
    class_type: &str,
) -> Result<(String, String), String> {
    if !stmt.type_name.is_empty() {
        return Ok((
            class_type.to_string(),
            java_class_to_descriptor_or_primitive(&stmt.type_name)?,
        ));
    }
    let field = resolve_field_with_env(env, class_type, &stmt.field_name, Some(is_static))?;
    Ok((field.declaring_type, field.field_type))
}

fn emit_let(
    ir: &mut DexIrBuilder,
    name: &str,
    type_name: Option<&str>,
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let Some(slot) = layout.local_regs.get(name) else {
        return Err(format!("local '{}' is not allocated", name));
    };
    if let Some(type_name) = type_name {
        let descriptor = java_class_to_descriptor_or_primitive(type_name)?;
        if slot.descriptor != descriptor {
            return Err(format!(
                "local '{}' type mismatch: declared {}, emitted {}",
                name, slot.descriptor, descriptor
            ));
        }
    }
    let src = emit_load_value(ir, value, &slot.descriptor, REG_TMP0, layout, dsl_ctx)?;
    emit_copy_value(ir, slot.reg, src, &slot.descriptor)?;
    Ok(())
}

fn emit_assign(
    ir: &mut DexIrBuilder,
    name: &str,
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let Some(slot) = layout.local_regs.get(name) else {
        return Err(format!("local '{}' is not allocated", name));
    };
    let src = emit_load_value(ir, value, &slot.descriptor, REG_TMP0, layout, dsl_ctx)?;
    emit_copy_value(ir, slot.reg, src, &slot.descriptor)?;
    Ok(())
}

fn emit_let_orig(
    ir: &mut DexIrBuilder,
    name: &str,
    type_name: Option<&str>,
    args: &DslOrigArgs,
    emit_ctx: &mut EmitContext<'_>,
) -> Result<(), String> {
    if emit_ctx.return_type == "V" {
        return Err("void orig() cannot be assigned to a local".to_string());
    }
    let slot = emit_ctx
        .layout
        .local_regs
        .get(name)
        .ok_or_else(|| format!("local '{}' is not allocated", name))?;
    let descriptor = if let Some(type_name) = type_name {
        java_class_to_descriptor_or_primitive(type_name)?
    } else {
        slot.descriptor.clone()
    };
    if slot.descriptor != descriptor {
        return Err(format!(
            "local '{}' type mismatch: declared {}, emitted {}",
            name, slot.descriptor, descriptor
        ));
    }
    if !value_descriptor_assignable_to(emit_ctx.return_type, &slot.descriptor) {
        return Err(format!(
            "orig() return type {} cannot be assigned to {}",
            emit_ctx.return_type, slot.descriptor
        ));
    }
    emit_orig_invoke(ir, args, emit_ctx)?;
    emit_move_result_value(ir, emit_ctx.return_type, slot.reg)?;
    Ok(())
}

fn emit_if_null(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    invert: bool,
    then_stmts: &[DslStmt],
    else_stmts: &[DslStmt],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    let reg = emit_load_value(
        ir,
        value,
        "Ljava/lang/Object;",
        REG_TMP0,
        emit_ctx.layout,
        emit_ctx.dsl_ctx,
    )?;
    let else_label = ir.new_label();
    let done_label = ir.new_label();
    if invert {
        ir.if_eqz(reg, else_label);
    } else {
        ir.if_nez(reg, else_label);
    }

    let then_returns = emit_statements(ir, then_stmts, emit_ctx)?;
    if !then_returns {
        ir.goto16(done_label);
    }
    ir.bind(else_label)?;
    let else_returns = emit_statements(ir, else_stmts, emit_ctx)?;
    ir.bind(done_label)?;
    Ok(then_returns && else_returns)
}

fn emit_if_bool(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    then_stmts: &[DslStmt],
    else_stmts: &[DslStmt],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    let reg = emit_load_cmp_value(ir, value, "Z", REG_TMP0, emit_ctx.layout, emit_ctx.dsl_ctx)?;
    let else_label = ir.new_label();
    let done_label = ir.new_label();
    ir.if_eqz(reg, else_label);

    let then_returns = emit_statements(ir, then_stmts, emit_ctx)?;
    if !then_returns {
        ir.goto16(done_label);
    }
    ir.bind(else_label)?;
    let else_returns = emit_statements(ir, else_stmts, emit_ctx)?;
    ir.bind(done_label)?;
    Ok(then_returns && else_returns)
}

fn cmp_expected_type(
    left: &DslValue,
    right: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<&'static str, String> {
    let left_desc = infer_cmp_descriptor(left, layout, dsl_ctx)?;
    let right_desc = infer_cmp_descriptor(right, layout, dsl_ctx)?;
    if left_desc == Some("Z") || right_desc == Some("Z") {
        Ok("Z")
    } else if left_desc == Some("I") || right_desc == Some("I") {
        Ok("I")
    } else {
        Ok("Ljava/lang/Object;")
    }
}

fn infer_cmp_descriptor(
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<Option<&'static str>, String> {
    let Some(desc) = infer_value_descriptor(value, layout, dsl_ctx)? else {
        return Ok(None);
    };
    Ok(match desc.as_str() {
        "I" => Some("I"),
        "Z" => Some("Z"),
        _ => None,
    })
}

fn emit_load_cmp_value(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    expected_type: &str,
    temp_reg: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let reg = emit_load_value(ir, value, expected_type, temp_reg, layout, dsl_ctx)?;
    if reg <= 0x0f {
        return Ok(reg);
    }
    let kind = value_kind_from_descriptor(expected_type)?;
    ir.move_from16(temp_reg, reg as u16, kind);
    Ok(temp_reg)
}

fn emit_if_cmp(
    ir: &mut DexIrBuilder,
    op: IfCmpOp,
    left: &DslValue,
    right: &DslValue,
    then_stmts: &[DslStmt],
    else_stmts: &[DslStmt],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    let expected_type = cmp_expected_type(left, right, emit_ctx.layout, emit_ctx.dsl_ctx)?;
    let left_reg = emit_load_cmp_value(ir, left, expected_type, REG_TMP0, emit_ctx.layout, emit_ctx.dsl_ctx)?;
    let right_reg = emit_load_cmp_value(ir, right, expected_type, REG_TMP1, emit_ctx.layout, emit_ctx.dsl_ctx)?;
    let else_label = ir.new_label();
    let done_label = ir.new_label();
    ir.if_cmp(op.invert(), left_reg, right_reg, else_label);

    let then_returns = emit_statements(ir, then_stmts, emit_ctx)?;
    if !then_returns {
        ir.goto16(done_label);
    }
    ir.bind(else_label)?;
    let else_returns = emit_statements(ir, else_stmts, emit_ctx)?;
    ir.bind(done_label)?;
    Ok(then_returns && else_returns)
}

fn emit_switch(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    cases: &[(i16, Vec<DslStmt>)],
    default_stmts: Option<&[DslStmt]>,
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    if cases.is_empty() {
        return Err("switch requires at least one case".to_string());
    }
    let mut seen = BTreeSet::new();
    for (literal, _) in cases {
        if !seen.insert(*literal) {
            return Err(format!("duplicate switch case {}", literal));
        }
    }

    let switch_reg = emit_load_cmp_value(ir, value, "I", REG_TMP0, emit_ctx.layout, emit_ctx.dsl_ctx)?;
    let default_label = ir.new_label();
    let done_label = ir.new_label();
    let case_labels = cases.iter().map(|_| ir.new_label()).collect::<Vec<_>>();

    let mut label_by_key = BTreeMap::new();
    for ((literal, _), label) in cases.iter().zip(case_labels.iter()) {
        label_by_key.insert(*literal, *label);
    }
    let min_key = *seen
        .iter()
        .next()
        .ok_or_else(|| "switch requires at least one case".to_string())?;
    let max_key = *seen
        .iter()
        .next_back()
        .ok_or_else(|| "switch requires at least one case".to_string())?;
    let range_len = (max_key as i32 - min_key as i32 + 1) as usize;
    if range_len <= cases.len() * 2 {
        let targets = (min_key..=max_key)
            .map(|key| *label_by_key.get(&key).unwrap_or(&default_label))
            .collect::<Vec<_>>();
        ir.packed_switch(switch_reg, min_key as i32, targets, default_label);
    } else {
        let keys = seen.iter().map(|key| *key as i32).collect::<Vec<_>>();
        let targets = seen
            .iter()
            .map(|key| *label_by_key.get(key).unwrap_or(&default_label))
            .collect::<Vec<_>>();
        ir.sparse_switch(switch_reg, keys, targets, default_label);
    }

    ir.bind(default_label)?;
    let default_returns = if let Some(stmts) = default_stmts {
        emit_statements(ir, stmts, emit_ctx)?
    } else {
        false
    };
    if !default_returns {
        ir.goto16(done_label);
    }

    let mut cases_all_return = true;
    for ((_, stmts), label) in cases.iter().zip(case_labels.iter()) {
        ir.bind(*label)?;
        let case_returns = emit_statements(ir, stmts, emit_ctx)?;
        if !case_returns {
            ir.goto16(done_label);
        }
        cases_all_return &= case_returns;
    }

    ir.bind(done_label)?;
    Ok(default_stmts.is_some() && default_returns && cases_all_return)
}

fn emit_cast(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    class_name: &str,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let ty = java_class_to_descriptor(class_name)?;
    let src = emit_load_value(ir, value, "Ljava/lang/Object;", REG_LAST_OBJECT, layout, dsl_ctx)?;
    let reg = emit_copy_object_if_needed(ir, src, REG_LAST_OBJECT);
    ir.check_cast(reg, ty);
    if reg != REG_LAST_OBJECT {
        ir.move_from16(REG_LAST_OBJECT, reg as u16, ValueKind::Object);
    }
    Ok(())
}

fn emit_new_array(
    ir: &mut DexIrBuilder,
    array_type_name: &str,
    size: &DslValue,
    sink: &FieldRef,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let array_type = java_class_to_descriptor_or_primitive(array_type_name)?;
    if !array_type.starts_with('[') {
        return Err(format!("newArray requires an array type, got '{}'", array_type_name));
    }
    let size_reg = emit_load_value(ir, size, "I", REG_TMP0, layout, dsl_ctx)?;
    let size_reg = emit_copy_field_value_if_needed(ir, size_reg, REG_TMP0, ValueKind::Narrow);
    ir.new_array(REG_LAST_OBJECT, size_reg, array_type);
    ir.sput_object(REG_LAST_OBJECT, sink.clone());
    Ok(())
}

fn emit_array_length_stmt(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let _ = emit_array_length_value(ir, array, REG_RESULT, layout, dsl_ctx)?;
    Ok(())
}

fn emit_array_get_stmt(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    index: &DslValue,
    type_name: Option<&str>,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let component_type = resolve_array_component_type(array, type_name, layout, dsl_ctx)?;
    let kind = value_kind_from_descriptor(&component_type)?;
    let dst = if matches!(kind, ValueKind::Object) {
        REG_LAST_OBJECT
    } else {
        REG_RESULT
    };
    let _ = emit_array_get_value(ir, array, index, &component_type, dst, layout, dsl_ctx)?;
    Ok(())
}

fn emit_array_put(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    index: &DslValue,
    type_name: Option<&str>,
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let component_type = resolve_array_component_type(array, type_name, layout, dsl_ctx)?;
    let kind = value_kind_from_descriptor(&component_type)?;
    let array_reg = emit_load_value(ir, array, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
    let array_reg = emit_copy_object_if_needed(ir, array_reg, REG_TMP1);
    let index_reg = emit_load_value(ir, index, "I", REG_TMP0, layout, dsl_ctx)?;
    let index_reg = emit_copy_field_value_if_needed(ir, index_reg, REG_TMP0, ValueKind::Narrow);
    let value_temp = if matches!(kind, ValueKind::Object) {
        REG_LAST_OBJECT
    } else {
        REG_LOOP_LIMIT
    };
    let value_reg = emit_load_value(ir, value, &component_type, value_temp, layout, dsl_ctx)?;
    let value_reg = emit_copy_field_value_if_needed(ir, value_reg, value_temp, kind);
    ir.aput(value_reg, array_reg, index_reg, kind);
    Ok(())
}

fn emit_if_instance_of(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    class_name: &str,
    then_stmts: &[DslStmt],
    else_stmts: &[DslStmt],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    let ty = java_class_to_descriptor(class_name)?;
    let src = emit_load_value(
        ir,
        value,
        "Ljava/lang/Object;",
        REG_TMP1,
        emit_ctx.layout,
        emit_ctx.dsl_ctx,
    )?;
    let obj = emit_copy_object_if_needed(ir, src, REG_TMP1);
    ir.instance_of(REG_TMP0, obj, ty.clone());

    let else_label = ir.new_label();
    let done_label = ir.new_label();
    ir.if_eqz(REG_TMP0, else_label);

    let then_returns = if let Some(key) = dsl_value_target_key(value) {
        emit_ctx.dsl_ctx.with_target_narrow_type(key, ty.clone(), |dsl_ctx| {
            let mut narrowed_ctx = EmitContext {
                layout: emit_ctx.layout,
                dsl_ctx,
                is_static: emit_ctx.is_static,
                local_count: emit_ctx.local_count,
                ins_size: emit_ctx.ins_size,
                target: emit_ctx.target,
                orig_backup: emit_ctx.orig_backup,
                target_is_interface: emit_ctx.target_is_interface,
                return_type: emit_ctx.return_type,
                sink: emit_ctx.sink,
            };
            emit_statements(ir, then_stmts, &mut narrowed_ctx)
        })?
    } else {
        emit_statements(ir, then_stmts, emit_ctx)?
    };
    if !then_returns {
        ir.goto16(done_label);
    }
    ir.bind(else_label)?;
    let else_returns = emit_statements(ir, else_stmts, emit_ctx)?;
    ir.bind(done_label)?;
    Ok(then_returns && else_returns)
}

#[derive(Clone, Copy)]
enum ManagedInvokeKind {
    Direct,
    Virtual,
    Interface,
    Static,
}

fn resolve_managed_invoke_kind(env: JniEnv, requested: DslCallKind, class_type: &str) -> ManagedInvokeKind {
    match requested {
        DslCallKind::Virtual if descriptor_is_interface(env, class_type) => ManagedInvokeKind::Interface,
        DslCallKind::Virtual => ManagedInvokeKind::Virtual,
        DslCallKind::Interface => ManagedInvokeKind::Interface,
        DslCallKind::Static => ManagedInvokeKind::Static,
    }
}

fn infer_call_arg_descriptors(
    stmt: &DslCallStmt,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<Vec<Option<String>>, String> {
    stmt.args
        .iter()
        .map(|arg| infer_value_descriptor(arg, layout, dsl_ctx))
        .collect::<Result<Vec<_>, _>>()
}

fn value_contains_invoke(value: &DslValue) -> bool {
    match value {
        DslValue::Call(_) | DslValue::NewObject { .. } => true,
        DslValue::UnaryOp { value, .. } => value_contains_invoke(value),
        DslValue::ArrayLength(value) => value_contains_invoke(value),
        DslValue::IntBinOp { left, right, .. } => value_contains_invoke(left) || value_contains_invoke(right),
        DslValue::Ternary {
            condition,
            then_value,
            else_value,
        } => {
            condition_contains_invoke(condition)
                || value_contains_invoke(then_value)
                || value_contains_invoke(else_value)
        }
        DslValue::Cast { value, .. } => value_contains_invoke(value),
        DslValue::ArrayGet { array, index, .. } => value_contains_invoke(array) || value_contains_invoke(index),
        DslValue::FieldGet { .. }
        | DslValue::Target(_)
        | DslValue::String(_)
        | DslValue::Int(_)
        | DslValue::Bool(_)
        | DslValue::Null => false,
    }
}

fn condition_contains_invoke(condition: &DslCondition) -> bool {
    match condition {
        DslCondition::Const(_) => false,
        DslCondition::Null { value, .. } | DslCondition::Bool { value } | DslCondition::InstanceOf { value, .. } => {
            value_contains_invoke(value)
        }
        DslCondition::Cmp { left, right, .. } => value_contains_invoke(left) || value_contains_invoke(right),
        DslCondition::And(left, right) | DslCondition::Or(left, right) => {
            condition_contains_invoke(left) || condition_contains_invoke(right)
        }
        DslCondition::Not(condition) => condition_contains_invoke(condition),
    }
}

fn emit_invoke_with_values(
    ir: &mut DexIrBuilder,
    kind: ManagedInvokeKind,
    method: MethodRef,
    receiver: Option<(u8, &str)>,
    params: &[String],
    args: &[DslValue],
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let has_wide = params.iter().any(|param| matches!(param.as_str(), "J" | "D"));
    if args.iter().any(value_contains_invoke) {
        return Err(
            "call expressions cannot be nested inside invoke arguments; assign the value to a let binding first"
                .to_string(),
        );
    }
    let mut regs = Vec::new();
    if let Some((receiver_reg, _)) = receiver {
        regs.push(receiver_reg);
    }

    let simple_35c = args.is_empty() && !has_wide && regs.len() <= 5 && regs.iter().all(|reg| *reg <= 0x0f);
    if simple_35c {
        match kind {
            ManagedInvokeKind::Direct => ir.invoke_direct(regs, method),
            ManagedInvokeKind::Virtual => ir.invoke_virtual(regs, method),
            ManagedInvokeKind::Interface => ir.invoke_interface(regs, method),
            ManagedInvokeKind::Static => ir.invoke_static(regs, method),
        }
        return Ok(());
    }

    let mut next = dsl_ctx.range_scratch_base;
    if let Some((receiver_reg, receiver_desc)) = receiver {
        let dst = checked_reg(next, "range receiver register")?;
        emit_copy_value(ir, dst, receiver_reg, receiver_desc)?;
        next += 1;
    }
    for (idx, arg) in args.iter().enumerate() {
        let dst = checked_reg(next, "range argument register")?;
        let src = emit_load_value(ir, arg, &params[idx], dst, layout, dsl_ctx)?;
        emit_copy_value(ir, dst, src, &params[idx])?;
        next = next
            .checked_add(descriptor_word_count(&params[idx]))
            .ok_or_else(|| "too many dex registers".to_string())?;
    }
    let arg_words = next
        .checked_sub(dsl_ctx.range_scratch_base)
        .ok_or_else(|| "invalid range invoke register layout".to_string())?;
    if arg_words > u8::MAX as u16 {
        return Err(format!("too many invoke argument words: {}", arg_words));
    }
    match kind {
        ManagedInvokeKind::Direct => ir.invoke_direct_range(dsl_ctx.range_scratch_base, arg_words as u8, method),
        ManagedInvokeKind::Virtual => ir.invoke_virtual_range(dsl_ctx.range_scratch_base, arg_words as u8, method),
        ManagedInvokeKind::Interface => ir.invoke_interface_range(dsl_ctx.range_scratch_base, arg_words as u8, method),
        ManagedInvokeKind::Static => ir.invoke_static_range(dsl_ctx.range_scratch_base, arg_words as u8, method),
    }
    Ok(())
}

fn emit_call(
    ir: &mut DexIrBuilder,
    stmt: &DslCallStmt,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<MethodRef, String> {
    let class_type = resolve_member_class_type(
        stmt.class_name.as_deref(),
        stmt.target.as_ref(),
        stmt.receiver.as_deref(),
        layout,
        dsl_ctx,
    )?;
    let arg_types = infer_call_arg_descriptors(stmt, layout, dsl_ctx)?;
    let (params, return_type, full_sig) =
        resolve_call_proto_with_arg_types(dsl_ctx.env, stmt, &class_type, Some(&arg_types))?;
    if params.len() != stmt.args.len() {
        return Err(format!(
            "{}.{}{} expects {} explicit args, got {}",
            stmt.class_label(),
            stmt.method_name,
            full_sig,
            params.len(),
            stmt.args.len()
        ));
    }
    let method = MethodRef::new(
        class_type.clone(),
        stmt.method_name.clone(),
        return_type.clone(),
        params.clone(),
    );

    let receiver = stmt
        .target
        .as_ref()
        .map(|target| resolve_target_reg(target, layout).map(|reg| (reg, class_type.as_str())))
        .transpose()?;
    let invoke_kind = resolve_managed_invoke_kind(dsl_ctx.env, stmt.kind, &class_type);
    if stmt.null_safe {
        let Some((receiver_reg, receiver_desc)) = receiver else {
            return Err("null-safe call requires a receiver".to_string());
        };
        if matches!(invoke_kind, ManagedInvokeKind::Static) {
            return Err("null-safe call is only valid for instance/interface methods".to_string());
        }
        let done_label = ir.new_label();
        ir.if_eqz(receiver_reg, done_label);
        emit_invoke_with_values(
            ir,
            invoke_kind,
            method.clone(),
            Some((receiver_reg, receiver_desc)),
            &params,
            &stmt.args,
            layout,
            dsl_ctx,
        )?;
        emit_discard_result(ir, &return_type)?;
        ir.bind(done_label)?;
        return Ok(method);
    }
    emit_invoke_with_values(
        ir,
        invoke_kind,
        method.clone(),
        receiver,
        &params,
        &stmt.args,
        layout,
        dsl_ctx,
    )?;
    emit_discard_result(ir, &return_type)?;
    Ok(method)
}

fn invoke_arg_words(has_receiver: bool, params: &[String]) -> Result<u16, String> {
    let mut words = if has_receiver { 1u16 } else { 0u16 };
    words = words
        .checked_add(descriptor_list_word_count(params)?)
        .ok_or_else(|| "too many dex registers".to_string())?;
    Ok(words)
}

pub(super) fn program_max_invoke_words(
    program: &DslProgram,
    target_params: &[String],
    is_static: bool,
) -> Result<u16, String> {
    statements_max_invoke_words(&program.stmts, target_params, is_static)
}

pub(super) fn program_int_expr_scratch_count(program: &DslProgram) -> u16 {
    statements_int_expr_scratch_count(&program.stmts)
}

fn statements_int_expr_scratch_count(stmts: &[DslStmt]) -> u16 {
    stmts.iter().map(stmt_int_expr_scratch_count).max().unwrap_or(0)
}

fn stmt_int_expr_scratch_count(stmt: &DslStmt) -> u16 {
    match stmt {
        DslStmt::Block(stmts) => statements_int_expr_scratch_count(stmts),
        DslStmt::Let { value, .. } | DslStmt::Assign { value, .. } => value_int_expr_scratch_count(value),
        DslStmt::LetOrig { args, .. } | DslStmt::ReturnOrig { args } => orig_args_int_expr_scratch_count(args),
        DslStmt::New { args, .. } => values_int_expr_scratch_count(args),
        DslStmt::NewArray { size, .. } => value_int_expr_scratch_count(size),
        DslStmt::Call(stmt) => stmt
            .receiver
            .as_ref()
            .map(|receiver| value_int_expr_scratch_count(receiver))
            .unwrap_or(0)
            .max(values_int_expr_scratch_count(&stmt.args)),
        DslStmt::Cast { value, .. } | DslStmt::ArrayLength { array: value } => value_int_expr_scratch_count(value),
        DslStmt::ArrayGet { array, index, .. } => {
            value_int_expr_scratch_count(array).max(value_int_expr_scratch_count(index))
        }
        DslStmt::ArrayPut {
            array, index, value, ..
        } => value_int_expr_scratch_count(array)
            .max(value_int_expr_scratch_count(index))
            .max(value_int_expr_scratch_count(value)),
        DslStmt::FieldRead { .. } => 0,
        DslStmt::FieldWrite { stmt, .. } => stmt.value.as_ref().map(value_int_expr_scratch_count).unwrap_or(0),
        DslStmt::IfNull {
            value,
            then_stmts,
            else_stmts,
            ..
        }
        | DslStmt::IfBool {
            value,
            then_stmts,
            else_stmts,
        }
        | DslStmt::IfInstanceOf {
            value,
            then_stmts,
            else_stmts,
            ..
        } => value_int_expr_scratch_count(value)
            .max(statements_int_expr_scratch_count(then_stmts))
            .max(statements_int_expr_scratch_count(else_stmts)),
        DslStmt::IfCmp {
            left,
            right,
            then_stmts,
            else_stmts,
            ..
        } => value_int_expr_scratch_count(left)
            .max(value_int_expr_scratch_count(right))
            .max(statements_int_expr_scratch_count(then_stmts))
            .max(statements_int_expr_scratch_count(else_stmts)),
        DslStmt::Switch {
            value,
            cases,
            default_stmts,
        } => {
            let mut count = value_int_expr_scratch_count(value);
            for (_, stmts) in cases {
                count = count.max(statements_int_expr_scratch_count(stmts));
            }
            if let Some(stmts) = default_stmts {
                count = count.max(statements_int_expr_scratch_count(stmts));
            }
            count
        }
        DslStmt::TryCatch {
            try_stmts, catch_stmts, ..
        } => statements_int_expr_scratch_count(try_stmts).max(statements_int_expr_scratch_count(catch_stmts)),
        DslStmt::ReturnValue { value } => value.as_ref().map(value_int_expr_scratch_count).unwrap_or(0),
        DslStmt::Throw { value } => value_int_expr_scratch_count(value),
    }
}

fn orig_args_int_expr_scratch_count(args: &DslOrigArgs) -> u16 {
    match args {
        DslOrigArgs::Original => 0,
        DslOrigArgs::Values(values) => values_int_expr_scratch_count(values),
    }
}

fn values_int_expr_scratch_count(values: &[DslValue]) -> u16 {
    values.iter().map(value_int_expr_scratch_count).max().unwrap_or(0)
}

fn value_int_expr_scratch_count(value: &DslValue) -> u16 {
    match value {
        DslValue::IntBinOp { op, left, right } => {
            if right_lit8_op(*op, right).is_some() {
                return value_int_expr_scratch_count(left);
            }
            if left_lit8_op(*op, left).is_some() {
                return value_int_expr_scratch_count(right);
            }
            let left_count = value_int_expr_scratch_count(left).max(1);
            let right_count = 1 + value_int_expr_scratch_count(right).max(1);
            left_count.max(right_count)
        }
        DslValue::UnaryOp { value, .. } => value_int_expr_scratch_count(value),
        DslValue::NewObject { args, .. } => values_int_expr_scratch_count(args),
        DslValue::Call(stmt) => stmt
            .receiver
            .as_ref()
            .map(|receiver| value_int_expr_scratch_count(receiver))
            .unwrap_or(0)
            .max(values_int_expr_scratch_count(&stmt.args)),
        DslValue::Ternary {
            condition,
            then_value,
            else_value,
        } => condition_int_expr_scratch_count(condition)
            .max(value_int_expr_scratch_count(then_value))
            .max(value_int_expr_scratch_count(else_value)),
        DslValue::Cast { value, .. } | DslValue::ArrayLength(value) => value_int_expr_scratch_count(value),
        DslValue::ArrayGet { array, index, .. } => {
            value_int_expr_scratch_count(array).max(value_int_expr_scratch_count(index))
        }
        DslValue::Target(_)
        | DslValue::String(_)
        | DslValue::Int(_)
        | DslValue::Bool(_)
        | DslValue::Null
        | DslValue::FieldGet { .. } => 0,
    }
}

fn condition_int_expr_scratch_count(condition: &DslCondition) -> u16 {
    match condition {
        DslCondition::Const(_) => 0,
        DslCondition::Null { value, .. } | DslCondition::Bool { value } | DslCondition::InstanceOf { value, .. } => {
            value_int_expr_scratch_count(value)
        }
        DslCondition::Cmp { left, right, .. } => {
            value_int_expr_scratch_count(left).max(value_int_expr_scratch_count(right))
        }
        DslCondition::And(left, right) | DslCondition::Or(left, right) => {
            condition_int_expr_scratch_count(left).max(condition_int_expr_scratch_count(right))
        }
        DslCondition::Not(condition) => condition_int_expr_scratch_count(condition),
    }
}

fn statements_max_invoke_words(stmts: &[DslStmt], target_params: &[String], is_static: bool) -> Result<u16, String> {
    let mut max_words = 0u16;
    for stmt in stmts {
        let words =
            match stmt {
                DslStmt::Block(stmts) => statements_max_invoke_words(stmts, target_params, is_static)?,
                DslStmt::Let { value, .. } | DslStmt::Assign { value, .. } => value_max_invoke_words(value)?,
                DslStmt::LetOrig { args, .. } => orig_args_max_invoke_words(args, target_params, is_static)?,
                DslStmt::New { ctor_sig, args, .. } => {
                    let params = if let Some(sig) = ctor_sig {
                        let (params, return_type) = parse_method_signature(sig)?;
                        if return_type != "V" {
                            return Err(format!("constructor signature must return void, got '{}'", return_type));
                        }
                        params
                    } else {
                        Vec::new()
                    };
                    let mut words = invoke_arg_words(true, &params)?;
                    for arg in args {
                        words = words.max(value_max_invoke_words(arg)?);
                    }
                    words
                }
                DslStmt::NewArray { size, .. } => value_max_invoke_words(size)?,
                DslStmt::Call(stmt) => {
                    let mut words = call_stmt_max_direct_words(stmt)?;
                    for arg in &stmt.args {
                        words = words.max(value_max_invoke_words(arg)?);
                    }
                    if let Some(receiver) = &stmt.receiver {
                        words = words.max(value_max_invoke_words(receiver)?);
                    }
                    words
                }
                DslStmt::IfNull {
                    value,
                    then_stmts,
                    else_stmts,
                    ..
                } => value_max_invoke_words(value)?
                    .max(statements_max_invoke_words(then_stmts, target_params, is_static)?)
                    .max(statements_max_invoke_words(else_stmts, target_params, is_static)?),
                DslStmt::IfBool {
                    value,
                    then_stmts,
                    else_stmts,
                } => value_max_invoke_words(value)?
                    .max(statements_max_invoke_words(then_stmts, target_params, is_static)?)
                    .max(statements_max_invoke_words(else_stmts, target_params, is_static)?),
                DslStmt::IfCmp {
                    left,
                    right,
                    then_stmts,
                    else_stmts,
                    ..
                } => value_max_invoke_words(left)?
                    .max(value_max_invoke_words(right)?)
                    .max(statements_max_invoke_words(then_stmts, target_params, is_static)?)
                    .max(statements_max_invoke_words(else_stmts, target_params, is_static)?),
                DslStmt::IfInstanceOf {
                    value,
                    then_stmts,
                    else_stmts,
                    ..
                } => value_max_invoke_words(value)?
                    .max(statements_max_invoke_words(then_stmts, target_params, is_static)?)
                    .max(statements_max_invoke_words(else_stmts, target_params, is_static)?),
                DslStmt::Switch {
                    value,
                    cases,
                    default_stmts,
                } => {
                    let mut words = value_max_invoke_words(value)?;
                    for (_, stmts) in cases {
                        words = words.max(statements_max_invoke_words(stmts, target_params, is_static)?);
                    }
                    if let Some(stmts) = default_stmts {
                        words = words.max(statements_max_invoke_words(stmts, target_params, is_static)?);
                    }
                    words
                }
                DslStmt::TryCatch {
                    try_stmts, catch_stmts, ..
                } => statements_max_invoke_words(try_stmts, target_params, is_static)?
                    .max(statements_max_invoke_words(catch_stmts, target_params, is_static)?),
                DslStmt::Cast { value, .. } => value_max_invoke_words(value)?,
                DslStmt::ArrayLength { array } => value_max_invoke_words(array)?,
                DslStmt::ArrayGet { array, index, .. } => {
                    value_max_invoke_words(array)?.max(value_max_invoke_words(index)?)
                }
                DslStmt::ArrayPut {
                    array, index, value, ..
                } => value_max_invoke_words(array)?
                    .max(value_max_invoke_words(index)?)
                    .max(value_max_invoke_words(value)?),
                DslStmt::FieldRead { stmt, .. } => stmt.target.as_ref().map(|_| 0).unwrap_or(0),
                DslStmt::FieldWrite { stmt, .. } => stmt
                    .value
                    .as_ref()
                    .map(value_max_invoke_words)
                    .transpose()?
                    .unwrap_or(0),
                DslStmt::ReturnOrig { args } => orig_args_max_invoke_words(args, target_params, is_static)?,
                DslStmt::ReturnValue { value } => value.as_ref().map(value_max_invoke_words).transpose()?.unwrap_or(0),
                DslStmt::Throw { value } => value_max_invoke_words(value)?,
            };
        max_words = max_words.max(words);
    }
    Ok(max_words)
}

fn value_max_invoke_words(value: &DslValue) -> Result<u16, String> {
    match value {
        DslValue::NewObject { ctor_sig, args, .. } => {
            let params = if let Some(sig) = ctor_sig {
                let (params, return_type) = parse_method_signature(sig)?;
                if return_type != "V" {
                    return Err(format!("constructor signature must return void, got '{}'", return_type));
                }
                params
            } else {
                Vec::new()
            };
            let mut words = invoke_arg_words(true, &params)?;
            for arg in args {
                words = words.max(value_max_invoke_words(arg)?);
            }
            Ok(words)
        }
        DslValue::Call(stmt) => {
            let mut words = call_stmt_max_direct_words(stmt)?;
            for arg in &stmt.args {
                words = words.max(value_max_invoke_words(arg)?);
            }
            if let Some(receiver) = &stmt.receiver {
                words = words.max(value_max_invoke_words(receiver)?);
            }
            Ok(words)
        }
        DslValue::ArrayLength(value) => value_max_invoke_words(value),
        DslValue::IntBinOp { left, right, .. } => Ok(value_max_invoke_words(left)?.max(value_max_invoke_words(right)?)),
        DslValue::UnaryOp { value, .. } => value_max_invoke_words(value),
        DslValue::Ternary {
            condition,
            then_value,
            else_value,
        } => Ok(condition_max_invoke_words(condition)?
            .max(value_max_invoke_words(then_value)?)
            .max(value_max_invoke_words(else_value)?)),
        DslValue::Cast { value, .. } => value_max_invoke_words(value),
        DslValue::ArrayGet { array, index, .. } => {
            Ok(value_max_invoke_words(array)?.max(value_max_invoke_words(index)?))
        }
        DslValue::FieldGet { .. }
        | DslValue::Target(_)
        | DslValue::String(_)
        | DslValue::Int(_)
        | DslValue::Bool(_)
        | DslValue::Null => Ok(0),
    }
}

fn call_stmt_max_direct_words(stmt: &DslCallStmt) -> Result<u16, String> {
    let has_receiver = stmt.target.is_some() || stmt.receiver.is_some();
    if stmt.sig.is_empty() {
        let receiver_words = if has_receiver { 1 } else { 0 };
        let arg_words = stmt
            .args
            .len()
            .checked_mul(2)
            .ok_or_else(|| "too many direct-call arguments".to_string())?;
        return (receiver_words + arg_words)
            .try_into()
            .map_err(|_| "too many direct-call argument words".to_string());
    }
    let params = parse_call_params(&stmt.sig)?;
    invoke_arg_words(has_receiver, &params)
}

fn condition_max_invoke_words(condition: &DslCondition) -> Result<u16, String> {
    match condition {
        DslCondition::Const(_) => Ok(0),
        DslCondition::Null { value, .. } | DslCondition::Bool { value } | DslCondition::InstanceOf { value, .. } => {
            value_max_invoke_words(value)
        }
        DslCondition::Cmp { left, right, .. } => Ok(value_max_invoke_words(left)?.max(value_max_invoke_words(right)?)),
        DslCondition::And(left, right) | DslCondition::Or(left, right) => {
            Ok(condition_max_invoke_words(left)?.max(condition_max_invoke_words(right)?))
        }
        DslCondition::Not(condition) => condition_max_invoke_words(condition),
    }
}

fn orig_args_max_invoke_words(args: &DslOrigArgs, target_params: &[String], is_static: bool) -> Result<u16, String> {
    let DslOrigArgs::Values(values) = args else {
        return Ok(0);
    };
    if values.len() != target_params.len() {
        return Err(format!(
            "orig(...) expects {} argument(s), got {}",
            target_params.len(),
            values.len()
        ));
    }
    let mut words = invoke_arg_words(!is_static, target_params)?;
    for value in values {
        words = words.max(value_max_invoke_words(value)?);
    }
    Ok(words)
}

pub(super) fn program_uses_orig(program: &DslProgram) -> bool {
    statements_use_orig(&program.stmts)
}

fn statements_use_orig(stmts: &[DslStmt]) -> bool {
    stmts.iter().any(stmt_uses_orig)
}

fn stmt_uses_orig(stmt: &DslStmt) -> bool {
    match stmt {
        DslStmt::Block(stmts) => statements_use_orig(stmts),
        DslStmt::ReturnOrig { .. } | DslStmt::LetOrig { .. } => true,
        DslStmt::IfNull {
            then_stmts, else_stmts, ..
        }
        | DslStmt::IfBool {
            then_stmts, else_stmts, ..
        }
        | DslStmt::IfCmp {
            then_stmts, else_stmts, ..
        }
        | DslStmt::IfInstanceOf {
            then_stmts, else_stmts, ..
        } => statements_use_orig(then_stmts) || statements_use_orig(else_stmts),
        DslStmt::Switch {
            cases, default_stmts, ..
        } => {
            cases.iter().any(|(_, stmts)| statements_use_orig(stmts))
                || default_stmts
                    .as_ref()
                    .map(|stmts| statements_use_orig(stmts))
                    .unwrap_or(false)
        }
        DslStmt::TryCatch {
            try_stmts, catch_stmts, ..
        } => statements_use_orig(try_stmts) || statements_use_orig(catch_stmts),
        _ => false,
    }
}

#[derive(Clone, Copy)]
struct ReturnFlow {
    falls_through: bool,
    has_non_orig_return: bool,
}

fn analyze_return_flow(stmts: &[DslStmt]) -> ReturnFlow {
    let mut has_non_orig_return = false;
    for stmt in stmts {
        let stmt_flow = match stmt {
            DslStmt::Block(stmts) => analyze_return_flow(stmts),
            DslStmt::ReturnOrig { .. } => ReturnFlow {
                falls_through: false,
                has_non_orig_return: false,
            },
            DslStmt::ReturnValue { .. } => ReturnFlow {
                falls_through: false,
                has_non_orig_return: true,
            },
            DslStmt::Throw { .. } => ReturnFlow {
                falls_through: false,
                has_non_orig_return: false,
            },
            DslStmt::IfNull {
                then_stmts, else_stmts, ..
            }
            | DslStmt::IfBool {
                then_stmts, else_stmts, ..
            }
            | DslStmt::IfCmp {
                then_stmts, else_stmts, ..
            }
            | DslStmt::IfInstanceOf {
                then_stmts, else_stmts, ..
            } => {
                let then_flow = analyze_return_flow(then_stmts);
                let else_flow = analyze_return_flow(else_stmts);
                ReturnFlow {
                    falls_through: then_flow.falls_through || else_flow.falls_through,
                    has_non_orig_return: then_flow.has_non_orig_return || else_flow.has_non_orig_return,
                }
            }
            DslStmt::Switch {
                cases, default_stmts, ..
            } => {
                let mut falls_through = default_stmts.is_none();
                let mut has_non_orig_return = false;
                for (_, stmts) in cases {
                    let flow = analyze_return_flow(stmts);
                    falls_through |= flow.falls_through;
                    has_non_orig_return |= flow.has_non_orig_return;
                }
                if let Some(stmts) = default_stmts {
                    let flow = analyze_return_flow(stmts);
                    falls_through |= flow.falls_through;
                    has_non_orig_return |= flow.has_non_orig_return;
                }
                ReturnFlow {
                    falls_through,
                    has_non_orig_return,
                }
            }
            DslStmt::TryCatch {
                try_stmts, catch_stmts, ..
            } => {
                let try_flow = analyze_return_flow(try_stmts);
                let catch_flow = analyze_return_flow(catch_stmts);
                ReturnFlow {
                    falls_through: try_flow.falls_through || catch_flow.falls_through,
                    has_non_orig_return: try_flow.has_non_orig_return,
                }
            }
            _ => ReturnFlow {
                falls_through: true,
                has_non_orig_return: false,
            },
        };
        has_non_orig_return |= stmt_flow.has_non_orig_return;
        if !stmt_flow.falls_through {
            return ReturnFlow {
                falls_through: false,
                has_non_orig_return,
            };
        }
    }
    ReturnFlow {
        falls_through: true,
        has_non_orig_return,
    }
}

pub(super) fn validate_orig_bypass_flow(program: &DslProgram) -> Result<(), String> {
    if program_uses_orig_value(program)? {
        return validate_orig_value_flow(program);
    }
    let flow = analyze_return_flow(&program.stmts);
    if flow.has_non_orig_return || flow.falls_through {
        return Err(
            "managed DSL uses orig(); every return path must end with return orig() or return orig(...) for high-frequency backup-orig routing"
                .to_string(),
        );
    }
    Ok(())
}

fn program_uses_orig_value(program: &DslProgram) -> Result<bool, String> {
    fn visit(stmts: &[DslStmt], nested: bool, count: &mut usize) -> Result<(), String> {
        for stmt in stmts {
            match stmt {
                DslStmt::Block(stmts) => visit(stmts, nested, count)?,
                DslStmt::LetOrig { .. } => {
                    if nested {
                        return Err("let x = orig(...) is only supported at top level".to_string());
                    }
                    *count += 1;
                }
                DslStmt::IfNull {
                    then_stmts, else_stmts, ..
                }
                | DslStmt::IfBool {
                    then_stmts, else_stmts, ..
                }
                | DslStmt::IfCmp {
                    then_stmts, else_stmts, ..
                }
                | DslStmt::IfInstanceOf {
                    then_stmts, else_stmts, ..
                } => {
                    visit(then_stmts, true, count)?;
                    visit(else_stmts, true, count)?;
                }
                DslStmt::Switch {
                    cases, default_stmts, ..
                } => {
                    for (_, stmts) in cases {
                        visit(stmts, true, count)?;
                    }
                    if let Some(stmts) = default_stmts {
                        visit(stmts, true, count)?;
                    }
                }
                DslStmt::TryCatch {
                    try_stmts, catch_stmts, ..
                } => {
                    visit(try_stmts, true, count)?;
                    visit(catch_stmts, true, count)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    let mut count = 0usize;
    visit(&program.stmts, false, &mut count)?;
    if count > 1 {
        return Err("managed DSL supports at most one let x = orig(...)".to_string());
    }
    Ok(count == 1)
}

fn statements_contain_return_orig(stmts: &[DslStmt]) -> bool {
    stmts.iter().any(|stmt| match stmt {
        DslStmt::Block(stmts) => statements_contain_return_orig(stmts),
        DslStmt::ReturnOrig { .. } => true,
        DslStmt::IfNull {
            then_stmts, else_stmts, ..
        }
        | DslStmt::IfBool {
            then_stmts, else_stmts, ..
        }
        | DslStmt::IfCmp {
            then_stmts, else_stmts, ..
        }
        | DslStmt::IfInstanceOf {
            then_stmts, else_stmts, ..
        } => statements_contain_return_orig(then_stmts) || statements_contain_return_orig(else_stmts),
        DslStmt::Switch {
            cases, default_stmts, ..
        } => {
            cases.iter().any(|(_, stmts)| statements_contain_return_orig(stmts))
                || default_stmts
                    .as_ref()
                    .map(|stmts| statements_contain_return_orig(stmts))
                    .unwrap_or(false)
        }
        DslStmt::TryCatch {
            try_stmts, catch_stmts, ..
        } => statements_contain_return_orig(try_stmts) || statements_contain_return_orig(catch_stmts),
        _ => false,
    })
}

fn validate_orig_value_flow(program: &DslProgram) -> Result<(), String> {
    let orig_pos = program
        .stmts
        .iter()
        .position(|stmt| matches!(stmt, DslStmt::LetOrig { .. }))
        .ok_or_else(|| "internal error: missing let x = orig(...)".to_string())?;
    if statements_contain_return_orig(&program.stmts) {
        return Err("let x = orig(...) cannot be mixed with return orig(...)".to_string());
    }
    if orig_pos != 0 {
        return Err("let x = orig(...) must be the first top-level statement".to_string());
    }
    let flow = analyze_return_flow(&program.stmts[orig_pos + 1..]);
    if flow.falls_through {
        return Err("managed DSL using let x = orig(...) must return on every path after orig(...)".to_string());
    }
    Ok(())
}

pub(super) fn collect_local_slots(
    local_descriptors: &BTreeMap<String, String>,
    first_reg: u16,
) -> Result<(BTreeMap<String, LocalSlot>, u16), String> {
    let mut slots = BTreeMap::new();
    let mut next = first_reg;
    for (name, descriptor) in local_descriptors {
        let reg = checked_reg(next, "local register")?;
        next = next
            .checked_add(descriptor_word_count(descriptor))
            .ok_or_else(|| "too many dex registers".to_string())?;
        slots.insert(
            name.clone(),
            LocalSlot {
                reg,
                descriptor: descriptor.clone(),
            },
        );
    }
    Ok((slots, next - first_reg))
}

pub(super) struct EmitContext<'a> {
    pub(super) layout: &'a HelperParamLayout,
    pub(super) dsl_ctx: &'a mut DslBuildContext,
    pub(super) is_static: bool,
    pub(super) local_count: u16,
    pub(super) ins_size: u16,
    pub(super) target: &'a MethodRef,
    pub(super) orig_backup: &'a MethodRef,
    pub(super) target_is_interface: bool,
    pub(super) return_type: &'a str,
    pub(super) sink: &'a FieldRef,
}

fn emit_orig_invoke(ir: &mut DexIrBuilder, args: &DslOrigArgs, emit_ctx: &mut EmitContext<'_>) -> Result<(), String> {
    match args {
        DslOrigArgs::Original => {
            ir.invoke_static_range(
                emit_ctx.local_count,
                emit_ctx.ins_size as u8,
                emit_ctx.orig_backup.clone(),
            );
        }
        DslOrigArgs::Values(values) => {
            if values.len() != emit_ctx.layout.arg_descriptors.len() {
                return Err(format!(
                    "orig(...) expects {} argument(s), got {}",
                    emit_ctx.layout.arg_descriptors.len(),
                    values.len()
                ));
            }
            let (kind, receiver, params, call_args) = if emit_ctx.is_static {
                (
                    ManagedInvokeKind::Static,
                    None,
                    emit_ctx.layout.arg_descriptors.clone(),
                    values.as_slice(),
                )
            } else {
                let this_desc = emit_ctx
                    .layout
                    .this_descriptor
                    .as_deref()
                    .ok_or_else(|| "missing this descriptor for orig(...)".to_string())?;
                let this_reg = emit_ctx
                    .layout
                    .this_reg
                    .ok_or_else(|| "missing this register for orig(...)".to_string())?;
                (
                    ManagedInvokeKind::Static,
                    Some((this_reg, this_desc)),
                    emit_ctx.layout.arg_descriptors.clone(),
                    values.as_slice(),
                )
            };
            emit_invoke_with_values(
                ir,
                kind,
                emit_ctx.orig_backup.clone(),
                receiver,
                &params,
                call_args,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
        }
    }
    Ok(())
}

fn emit_return_orig(ir: &mut DexIrBuilder, args: &DslOrigArgs, emit_ctx: &mut EmitContext<'_>) -> Result<(), String> {
    emit_orig_invoke(ir, args, emit_ctx)?;
    emit_return_from_orig(ir, emit_ctx.return_type)
}

fn emit_return_value(
    ir: &mut DexIrBuilder,
    value: Option<&DslValue>,
    emit_ctx: &mut EmitContext<'_>,
) -> Result<(), String> {
    match emit_ctx.return_type {
        "V" => {
            if value.is_some() {
                return Err("void method can only use return; or return orig(...);".to_string());
            }
            ir.return_void();
        }
        "J" | "D" => {
            let Some(value) = value else {
                return Err(format!(
                    "method returning {} requires return value",
                    emit_ctx.return_type
                ));
            };
            let reg = emit_load_value(
                ir,
                value,
                emit_ctx.return_type,
                REG_TMP0,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            ir.return_wide(reg);
        }
        ret if return_is_object(ret) => {
            let Some(value) = value else {
                return Err(format!(
                    "method returning {} requires return value",
                    emit_ctx.return_type
                ));
            };
            let reg = emit_load_value(
                ir,
                value,
                emit_ctx.return_type,
                REG_TMP0,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            ir.return_object(reg);
        }
        "Z" | "B" | "C" | "S" | "I" | "F" => {
            let Some(value) = value else {
                return Err(format!(
                    "method returning {} requires return value",
                    emit_ctx.return_type
                ));
            };
            let reg = emit_load_value(
                ir,
                value,
                emit_ctx.return_type,
                REG_TMP0,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            ir.return_value(reg);
        }
        other => return Err(format!("unsupported direct return type '{}'", other)),
    }
    Ok(())
}

fn emit_throw(ir: &mut DexIrBuilder, value: &DslValue, emit_ctx: &mut EmitContext<'_>) -> Result<(), String> {
    let reg = emit_load_value(
        ir,
        value,
        "Ljava/lang/Object;",
        REG_TMP0,
        emit_ctx.layout,
        emit_ctx.dsl_ctx,
    )?;
    ir.check_cast(reg, "Ljava/lang/Throwable;");
    ir.throw_value(reg);
    Ok(())
}

fn emit_try_catch(
    ir: &mut DexIrBuilder,
    try_stmts: &[DslStmt],
    catch_type: &str,
    catch_name: &str,
    catch_stmts: &[DslStmt],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    let catch_descriptor = java_class_to_descriptor(catch_type)?;
    let catch_slot = emit_ctx
        .layout
        .local_regs
        .get(catch_name)
        .ok_or_else(|| format!("catch local '{}' is not allocated", catch_name))?;
    if catch_slot.descriptor != catch_descriptor {
        return Err(format!(
            "catch local '{}' type mismatch: declared {}, emitted {}",
            catch_name, catch_slot.descriptor, catch_descriptor
        ));
    }

    let try_start = ir.new_label();
    let try_end = ir.new_label();
    let catch_handler = ir.new_label();
    let done = ir.new_label();

    ir.bind(try_start)?;
    let try_returns = emit_statements(ir, try_stmts, emit_ctx)?;
    ir.bind(try_end)?;
    if !try_returns {
        ir.goto16(done);
    }

    ir.bind(catch_handler)?;
    ir.move_exception(catch_slot.reg);
    let catch_returns = emit_statements(ir, catch_stmts, emit_ctx)?;
    ir.bind(done)?;
    ir.add_try_item(try_start, try_end, catch_descriptor, catch_handler);

    Ok(try_returns && catch_returns)
}

fn emit_statement(ir: &mut DexIrBuilder, stmt: &DslStmt, emit_ctx: &mut EmitContext<'_>) -> Result<bool, String> {
    match stmt {
        DslStmt::Block(stmts) => emit_statements(ir, stmts, emit_ctx),
        DslStmt::Let { name, type_name, value } => {
            emit_let(ir, name, type_name.as_deref(), value, emit_ctx.layout, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::Assign { name, value } => {
            emit_assign(ir, name, value, emit_ctx.layout, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::LetOrig { name, type_name, args } => {
            emit_let_orig(ir, name, type_name.as_deref(), args, emit_ctx)?;
            Ok(false)
        }
        DslStmt::New {
            class_name,
            ctor_sig,
            args,
        } => {
            emit_new_object(
                ir,
                class_name,
                ctor_sig.as_deref(),
                args,
                emit_ctx.sink,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            Ok(false)
        }
        DslStmt::NewArray { array_type_name, size } => {
            emit_new_array(
                ir,
                array_type_name,
                size,
                emit_ctx.sink,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            Ok(false)
        }
        DslStmt::Call(stmt) => {
            emit_call(ir, stmt, emit_ctx.layout, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::Cast { value, class_name } => {
            emit_cast(ir, value, class_name, emit_ctx.layout, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::ArrayLength { array } => {
            emit_array_length_stmt(ir, array, emit_ctx.layout, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::ArrayGet {
            array,
            index,
            type_name,
        } => {
            emit_array_get_stmt(
                ir,
                array,
                index,
                type_name.as_deref(),
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            Ok(false)
        }
        DslStmt::ArrayPut {
            array,
            index,
            type_name,
            value,
        } => {
            emit_array_put(
                ir,
                array,
                index,
                type_name.as_deref(),
                value,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            Ok(false)
        }
        DslStmt::FieldRead { stmt, is_static } => {
            emit_field_read(ir, stmt, emit_ctx.layout, *is_static, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::FieldWrite { stmt, is_static } => {
            emit_field_write(ir, stmt, emit_ctx.layout, *is_static, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::IfNull {
            value,
            invert,
            then_stmts,
            else_stmts,
        } => emit_if_null(ir, value, *invert, then_stmts, else_stmts, emit_ctx),
        DslStmt::IfBool {
            value,
            then_stmts,
            else_stmts,
        } => emit_if_bool(ir, value, then_stmts, else_stmts, emit_ctx),
        DslStmt::IfCmp {
            op,
            left,
            right,
            then_stmts,
            else_stmts,
        } => emit_if_cmp(ir, *op, left, right, then_stmts, else_stmts, emit_ctx),
        DslStmt::IfInstanceOf {
            value,
            class_name,
            then_stmts,
            else_stmts,
        } => emit_if_instance_of(ir, value, class_name, then_stmts, else_stmts, emit_ctx),
        DslStmt::Switch {
            value,
            cases,
            default_stmts,
        } => emit_switch(ir, value, cases, default_stmts.as_deref(), emit_ctx),
        DslStmt::TryCatch {
            try_stmts,
            catch_type,
            catch_name,
            catch_stmts,
        } => emit_try_catch(ir, try_stmts, catch_type, catch_name, catch_stmts, emit_ctx),
        DslStmt::ReturnOrig { args } => {
            emit_return_orig(ir, args, emit_ctx)?;
            Ok(true)
        }
        DslStmt::ReturnValue { value } => {
            emit_return_value(ir, value.as_ref(), emit_ctx)?;
            Ok(true)
        }
        DslStmt::Throw { value } => {
            emit_throw(ir, value, emit_ctx)?;
            Ok(true)
        }
    }
}

pub(super) fn emit_statements(
    ir: &mut DexIrBuilder,
    stmts: &[DslStmt],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    for stmt in stmts {
        if emit_statement(ir, stmt, emit_ctx)? {
            return Ok(true);
        }
    }
    Ok(false)
}
