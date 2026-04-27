use std::collections::BTreeMap;

use super::dsl::{
    DslCallKind, DslCallStmt, DslCondition, DslFieldStmt, DslOrigArgs, DslProgram, DslStmt, DslTarget, DslUnaryOp,
    DslValue,
};
use super::{
    array_component_descriptor, common_value_descriptor_with_env, java_class_to_descriptor,
    java_class_to_descriptor_or_primitive, parse_method_signature, resolve_call_proto_with_arg_types,
    resolve_field_with_env, return_is_object,
};
use crate::jsapi::java::jni_core::JniEnv;

struct DslSemanticContext {
    env: JniEnv,
    this_descriptor: Option<String>,
    arg_descriptors: Vec<String>,
    target_return_type: String,
    local_descriptors: BTreeMap<String, String>,
    target_narrow_types: BTreeMap<DslTargetKey, Option<String>>,
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

fn dsl_target_label(target: &DslTarget) -> String {
    match target {
        DslTarget::This => "this".to_string(),
        DslTarget::Arg(index) => format!("arg{}", index),
        DslTarget::Local(name) => name.clone(),
        DslTarget::Last => "last".to_string(),
        DslTarget::Result => "result".to_string(),
    }
}

fn value_descriptor_assignable_to(src: &str, dst: &str) -> bool {
    src == dst || (return_is_object(src) && return_is_object(dst))
}

fn nonnull_key_for_value(value: &DslValue) -> Option<DslTargetKey> {
    let DslValue::Target(target) = value else {
        return None;
    };
    dsl_target_key(target)
}

fn condition_facts_when_true(condition: &DslCondition) -> Vec<(DslTargetKey, Option<String>)> {
    match condition {
        DslCondition::Null { value, invert: true } => nonnull_key_for_value(value)
            .into_iter()
            .map(|key| (key, None))
            .collect(),
        DslCondition::InstanceOf { value, class_name } => nonnull_key_for_value(value)
            .into_iter()
            .map(|key| {
                (
                    key,
                    Some(java_class_to_descriptor(class_name).unwrap_or_else(|_| class_name.clone())),
                )
            })
            .collect(),
        DslCondition::And(left, right) => {
            let mut facts = condition_facts_when_true(left);
            facts.extend(condition_facts_when_true(right));
            facts
        }
        DslCondition::Not(condition) => condition_facts_when_false(condition),
        _ => Vec::new(),
    }
}

fn condition_facts_when_false(condition: &DslCondition) -> Vec<(DslTargetKey, Option<String>)> {
    match condition {
        DslCondition::Null { value, invert: false } => nonnull_key_for_value(value)
            .into_iter()
            .map(|key| (key, None))
            .collect(),
        DslCondition::Or(left, right) => {
            let mut facts = condition_facts_when_false(left);
            facts.extend(condition_facts_when_false(right));
            facts
        }
        DslCondition::Not(condition) => condition_facts_when_true(condition),
        _ => Vec::new(),
    }
}

impl DslSemanticContext {
    fn new(
        env: JniEnv,
        is_static: bool,
        target_type: String,
        target_params: Vec<String>,
        target_return_type: String,
    ) -> Self {
        Self {
            env,
            this_descriptor: if is_static { None } else { Some(target_type) },
            arg_descriptors: target_params,
            target_return_type,
            local_descriptors: BTreeMap::new(),
            target_narrow_types: BTreeMap::new(),
        }
    }

    fn resolve_target_descriptor(&self, target: &DslTarget) -> Result<String, String> {
        if let Some(key) = dsl_target_key(target) {
            if let Some(Some(desc)) = self.target_narrow_types.get(&key) {
                return Ok(desc.clone());
            }
        }
        match target {
            DslTarget::This => self
                .this_descriptor
                .clone()
                .ok_or_else(|| "static target has no this descriptor".to_string()),
            DslTarget::Arg(index) => self
                .arg_descriptors
                .get(*index)
                .cloned()
                .ok_or_else(|| format!("argument {} does not exist", index)),
            DslTarget::Local(name) => self
                .local_descriptors
                .get(name)
                .cloned()
                .ok_or_else(|| format!("local '{}' is not declared", name)),
            DslTarget::Last | DslTarget::Result => {
                Err("target class cannot be inferred for last/result; pass the class name explicitly".to_string())
            }
        }
    }

    fn resolve_member_class_type(
        &self,
        explicit_class_name: Option<&str>,
        target: Option<&DslTarget>,
        receiver: Option<&DslValue>,
    ) -> Result<String, String> {
        if let Some(class_name) = explicit_class_name {
            return java_class_to_descriptor(class_name);
        }
        if let Some(receiver) = receiver {
            let Some(desc) = self.infer_value_descriptor(receiver)? else {
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
        let desc = self.resolve_target_descriptor(target)?;
        if !desc.starts_with('L') || !desc.ends_with(';') {
            return Err(format!(
                "target class can only be inferred from object locals/args, got {}",
                desc
            ));
        }
        Ok(desc)
    }

    fn infer_value_descriptor(&self, value: &DslValue) -> Result<Option<String>, String> {
        match value {
            DslValue::Target(target) => self.resolve_target_descriptor(target).map(Some),
            DslValue::String(_) => Ok(Some("Ljava/lang/String;".to_string())),
            DslValue::Int(_) | DslValue::IntBinOp { .. } | DslValue::ArrayLength(_) => Ok(Some("I".to_string())),
            DslValue::UnaryOp { op, .. } => match op {
                DslUnaryOp::Neg | DslUnaryOp::BitNot => Ok(Some("I".to_string())),
                DslUnaryOp::BoolNot => Ok(Some("Z".to_string())),
            },
            DslValue::Ternary {
                then_value, else_value, ..
            } => {
                let then_desc = self.infer_value_descriptor(then_value)?;
                let else_desc = self.infer_value_descriptor(else_value)?;
                common_value_descriptor_with_env(then_desc, else_desc, self.env)
            }
            DslValue::Bool(_) => Ok(Some("Z".to_string())),
            DslValue::Null => Ok(None),
            DslValue::Call(stmt) => {
                let class_type = self.resolve_member_class_type(
                    stmt.class_name.as_deref(),
                    stmt.target.as_ref(),
                    stmt.receiver.as_deref(),
                )?;
                let arg_types = self.infer_call_arg_descriptors(stmt)?;
                let (_, return_type, _) =
                    resolve_call_proto_with_arg_types(self.env, stmt, &class_type, Some(&arg_types))?;
                if return_type == "V" {
                    Ok(None)
                } else {
                    Ok(Some(return_type))
                }
            }
            DslValue::NewObject { class_name, .. } => java_class_to_descriptor(class_name).map(Some),
            DslValue::FieldGet { stmt, is_static } => self.resolve_field_descriptor(stmt, *is_static).map(Some),
            DslValue::Cast { class_name, .. } => java_class_to_descriptor(class_name).map(Some),
            DslValue::ArrayGet { type_name, array, .. } => match type_name {
                Some(type_name) => java_class_to_descriptor_or_primitive(type_name).map(Some),
                None => {
                    let Some(array_desc) = self.infer_value_descriptor(array)? else {
                        return Ok(None);
                    };
                    array_component_descriptor(&array_desc).map(Some)
                }
            },
        }
    }

    fn is_known_nonnull_target(&self, target: &DslTarget) -> bool {
        matches!(target, DslTarget::This)
            || dsl_target_key(target)
                .map(|key| self.target_narrow_types.contains_key(&key))
                .unwrap_or(false)
    }

    fn validate_receiver_nonnull(&self, stmt: &DslCallStmt, class_type: &str) -> Result<(), String> {
        if stmt.kind == DslCallKind::Static || !return_is_object(class_type) {
            return Ok(());
        }
        if stmt.receiver.is_some() {
            return Ok(());
        }
        let Some(target) = stmt.target.as_ref() else {
            return Ok(());
        };
        if self.is_known_nonnull_target(target) {
            return Ok(());
        }
        Err(format!(
            "receiver '{}' may be null before calling {}.{}; guard it with '{} != null' first",
            dsl_target_label(target),
            stmt.class_label(),
            stmt.method_name,
            dsl_target_label(target)
        ))
    }

    fn validate_value(&mut self, value: &DslValue) -> Result<(), String> {
        self.validate_value_inner(value, false)
    }

    fn validate_bool_condition_value(&mut self, value: &DslValue) -> Result<(), String> {
        self.validate_value_inner(value, true)?;
        let Some(desc) = self.infer_value_descriptor(value)? else {
            return Err("boolean condition requires boolean, got null/void".to_string());
        };
        if desc != "Z" {
            return Err(format!("boolean condition requires boolean, got {}", desc));
        }
        Ok(())
    }

    fn validate_value_inner(&mut self, value: &DslValue, require_nonnull_receiver: bool) -> Result<(), String> {
        match value {
            DslValue::Target(target) => {
                self.resolve_target_descriptor(target)?;
            }
            DslValue::String(_) | DslValue::Int(_) | DslValue::Bool(_) | DslValue::Null => {}
            DslValue::UnaryOp { op, value } => {
                self.validate_value_inner(value, require_nonnull_receiver)?;
                let Some(desc) = self.infer_value_descriptor(value)? else {
                    return Err("unary expression type cannot be inferred".to_string());
                };
                match op {
                    DslUnaryOp::Neg | DslUnaryOp::BitNot if desc != "I" => {
                        return Err(format!("int unary expression requires int, got {}", desc));
                    }
                    DslUnaryOp::BoolNot if desc != "Z" => {
                        return Err(format!("boolean unary expression requires boolean, got {}", desc));
                    }
                    _ => {}
                }
            }
            DslValue::ArrayLength(value) => {
                self.validate_value_inner(value, require_nonnull_receiver)?;
            }
            DslValue::IntBinOp { left, right, .. } => {
                self.validate_value_inner(left, require_nonnull_receiver)?;
                self.validate_value_inner(right, require_nonnull_receiver)?;
            }
            DslValue::Ternary {
                condition,
                then_value,
                else_value,
            } => {
                self.validate_condition(condition)?;
                let true_facts = condition_facts_when_true(condition);
                self.validate_with_target_facts(&true_facts, |ctx| {
                    ctx.validate_value_inner(then_value, require_nonnull_receiver)
                })?;
                let false_facts = condition_facts_when_false(condition);
                self.validate_with_target_facts(&false_facts, |ctx| {
                    ctx.validate_value_inner(else_value, require_nonnull_receiver)
                })?;
                let _ = self.infer_value_descriptor(value)?;
            }
            DslValue::Cast { value, class_name } => {
                self.validate_value_inner(value, require_nonnull_receiver)?;
                java_class_to_descriptor(class_name)?;
            }
            DslValue::ArrayGet { array, index, .. } => {
                self.validate_value_inner(array, require_nonnull_receiver)?;
                self.validate_value_inner(index, require_nonnull_receiver)?;
                if self.infer_value_descriptor(array)?.is_none() {
                    return Err("array element type cannot be inferred; use arr[index: Type]".to_string());
                }
            }
            DslValue::NewObject {
                class_name,
                ctor_sig,
                args,
            } => {
                java_class_to_descriptor(class_name)?;
                let params = if let Some(sig) = ctor_sig {
                    let (params, return_type) = parse_method_signature(sig)?;
                    if return_type != "V" {
                        return Err(format!("constructor signature must return void, got '{}'", return_type));
                    }
                    params
                } else {
                    if args.is_empty() {
                        Vec::new()
                    } else {
                        return Err(
                            "constructor arguments must include a full JNI signature or parameter type list"
                                .to_string(),
                        );
                    }
                };
                if params.len() != args.len() {
                    return Err(format!(
                        "constructor expects {} explicit args, got {}",
                        params.len(),
                        args.len()
                    ));
                }
                for arg in args {
                    self.validate_value_inner(arg, require_nonnull_receiver)?;
                }
            }
            DslValue::Call(stmt) => {
                if let Some(receiver) = &stmt.receiver {
                    self.validate_value_inner(receiver, require_nonnull_receiver)?;
                }
                self.validate_call_inner(stmt, require_nonnull_receiver)?;
            }
            DslValue::FieldGet { stmt, is_static } => {
                if let Some(receiver) = &stmt.receiver {
                    self.validate_value_inner(receiver, require_nonnull_receiver)?;
                }
                self.validate_field(stmt, *is_static)?;
            }
        }
        Ok(())
    }

    fn validate_condition(&mut self, condition: &DslCondition) -> Result<(), String> {
        match condition {
            DslCondition::Const(_) => {}
            DslCondition::Null { value, .. } => {
                self.validate_value(value)?;
            }
            DslCondition::Bool { value } => {
                self.validate_bool_condition_value(value)?;
            }
            DslCondition::Cmp { left, right, .. } => {
                self.validate_value(left)?;
                self.validate_value(right)?;
            }
            DslCondition::InstanceOf { value, class_name } => {
                self.validate_value(value)?;
                java_class_to_descriptor(class_name)?;
            }
            DslCondition::And(left, right) => {
                self.validate_condition(left)?;
                let facts = condition_facts_when_true(left);
                self.validate_with_target_facts(&facts, |ctx| ctx.validate_condition(right))?;
            }
            DslCondition::Or(left, right) => {
                self.validate_condition(left)?;
                let facts = condition_facts_when_false(left);
                self.validate_with_target_facts(&facts, |ctx| ctx.validate_condition(right))?;
            }
            DslCondition::Not(condition) => self.validate_condition(condition)?,
        }
        Ok(())
    }

    fn validate_call(&mut self, stmt: &DslCallStmt) -> Result<(), String> {
        self.validate_call_inner(stmt, false)
    }

    fn validate_call_inner(&mut self, stmt: &DslCallStmt, require_nonnull_receiver: bool) -> Result<(), String> {
        if stmt.target.is_some() && stmt.receiver.is_some() {
            return Err("method call cannot use both target and receiver expression".to_string());
        }
        if stmt.kind == DslCallKind::Static && stmt.receiver.is_some() {
            return Err("static method call cannot use a receiver expression".to_string());
        }
        if stmt.null_safe && stmt.kind == DslCallKind::Static {
            return Err("null-safe call is only valid for instance/interface methods".to_string());
        }
        if stmt.null_safe && stmt.target.is_none() && stmt.receiver.is_none() {
            return Err("null-safe call requires a receiver".to_string());
        }
        let class_type = self.resolve_member_class_type(
            stmt.class_name.as_deref(),
            stmt.target.as_ref(),
            stmt.receiver.as_deref(),
        )?;
        let arg_types = self.infer_call_arg_descriptors(stmt)?;
        let (params, _, full_sig) = resolve_call_proto_with_arg_types(self.env, stmt, &class_type, Some(&arg_types))?;
        if require_nonnull_receiver {
            self.validate_receiver_nonnull(stmt, &class_type)?;
        }
        if let Some(receiver) = &stmt.receiver {
            self.validate_value_inner(receiver, require_nonnull_receiver)?;
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
        for arg in &stmt.args {
            self.validate_value_inner(arg, require_nonnull_receiver)?;
        }
        Ok(())
    }

    fn infer_call_arg_descriptors(&self, stmt: &DslCallStmt) -> Result<Vec<Option<String>>, String> {
        stmt.args
            .iter()
            .map(|arg| self.infer_value_descriptor(arg))
            .collect::<Result<Vec<_>, _>>()
    }

    fn resolve_field_descriptor(&self, stmt: &DslFieldStmt, is_static: bool) -> Result<String, String> {
        if !stmt.type_name.is_empty() {
            return java_class_to_descriptor_or_primitive(&stmt.type_name);
        }
        let class_type = self.resolve_member_class_type(
            stmt.class_name.as_deref(),
            stmt.target.as_ref(),
            stmt.receiver.as_deref(),
        )?;
        resolve_field_with_env(self.env, &class_type, &stmt.field_name, Some(is_static)).map(|field| field.field_type)
    }

    fn validate_field(&mut self, stmt: &DslFieldStmt, is_static: bool) -> Result<(), String> {
        if stmt.target.is_some() && stmt.receiver.is_some() {
            return Err("field access cannot use both target and receiver expression".to_string());
        }
        self.resolve_member_class_type(
            stmt.class_name.as_deref(),
            stmt.target.as_ref(),
            stmt.receiver.as_deref(),
        )?;
        if let Some(receiver) = &stmt.receiver {
            self.validate_value(receiver)?;
        }
        let descriptor = self.resolve_field_descriptor(stmt, is_static)?;
        if let Some(value) = &stmt.value {
            self.validate_value(value)?;
            if let Some(value_desc) = self.infer_value_descriptor(value)? {
                if !value_descriptor_assignable_to(&value_desc, &descriptor) {
                    return Err(format!(
                        "field '{}' type mismatch: cannot assign {} to {}",
                        stmt.field_name, value_desc, descriptor
                    ));
                }
            } else if !return_is_object(&descriptor) {
                return Err(format!(
                    "field '{}' type mismatch: cannot assign null/void to {}",
                    stmt.field_name, descriptor
                ));
            }
        }
        Ok(())
    }

    fn validate_orig_args(&mut self, args: &DslOrigArgs) -> Result<(), String> {
        let DslOrigArgs::Values(values) = args else {
            return Ok(());
        };
        if values.len() != self.arg_descriptors.len() {
            return Err(format!(
                "orig(...) expects {} argument(s), got {}",
                self.arg_descriptors.len(),
                values.len()
            ));
        }
        for value in values {
            self.validate_value(value)?;
        }
        Ok(())
    }

    fn validate_stmts(&mut self, stmts: &[DslStmt]) -> Result<(), String> {
        for stmt in stmts {
            self.validate_stmt(stmt)?;
        }
        Ok(())
    }

    fn validate_stmts_with_nonnull_value(&mut self, value: &DslValue, stmts: &[DslStmt]) -> Result<(), String> {
        let Some(key) = nonnull_key_for_value(value) else {
            return self.validate_stmts(stmts);
        };
        self.validate_with_target_facts(&[(key, None)], |ctx| ctx.validate_stmts(stmts))
    }

    fn validate_with_target_facts<F>(&mut self, facts: &[(DslTargetKey, Option<String>)], f: F) -> Result<(), String>
    where
        F: FnOnce(&mut Self) -> Result<(), String>,
    {
        let previous = facts
            .iter()
            .map(|(key, desc)| {
                let old = self.target_narrow_types.insert(key.clone(), desc.clone());
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

    fn validate_stmt(&mut self, stmt: &DslStmt) -> Result<(), String> {
        match stmt {
            DslStmt::Block(stmts) => self.validate_stmts(stmts)?,
            DslStmt::Let { name, type_name, value } => {
                self.validate_value(value)?;
                let descriptor = if let Some(type_name) = type_name {
                    let descriptor = java_class_to_descriptor_or_primitive(type_name)?;
                    if let Some(value_desc) = self.infer_value_descriptor(value)? {
                        if !value_descriptor_assignable_to(&value_desc, &descriptor) {
                            return Err(format!(
                                "local '{}' type mismatch: cannot assign {} to {}",
                                name, value_desc, descriptor
                            ));
                        }
                    } else if !return_is_object(&descriptor) {
                        return Err(format!(
                            "local '{}' type mismatch: cannot assign null/void to {}",
                            name, descriptor
                        ));
                    }
                    descriptor
                } else {
                    self.infer_value_descriptor(value)?
                        .ok_or_else(|| format!("local '{}' type cannot be inferred", name))?
                };
                self.local_descriptors.entry(name.clone()).or_insert(descriptor);
            }
            DslStmt::Assign { name, value } => {
                let Some(descriptor) = self.local_descriptors.get(name).cloned() else {
                    return Err(format!("local '{}' is not declared", name));
                };
                self.validate_value(value)?;
                if let Some(value_desc) = self.infer_value_descriptor(value)? {
                    if !value_descriptor_assignable_to(&value_desc, &descriptor) {
                        return Err(format!(
                            "local '{}' type mismatch: cannot assign {} to {}",
                            name, value_desc, descriptor
                        ));
                    }
                } else if !return_is_object(&descriptor) {
                    return Err(format!(
                        "local '{}' type mismatch: cannot assign null/void to {}",
                        name, descriptor
                    ));
                }
            }
            DslStmt::LetOrig { name, type_name, args } => {
                if self.target_return_type == "V" {
                    return Err("void orig() cannot be assigned to a local".to_string());
                }
                let descriptor = if let Some(type_name) = type_name {
                    let descriptor = java_class_to_descriptor_or_primitive(type_name)?;
                    if !value_descriptor_assignable_to(&self.target_return_type, &descriptor) {
                        return Err(format!(
                            "orig() return type {} cannot be assigned to {}",
                            self.target_return_type, descriptor
                        ));
                    }
                    descriptor
                } else {
                    self.target_return_type.clone()
                };
                self.validate_orig_args(args)?;
                self.local_descriptors.entry(name.clone()).or_insert(descriptor);
            }
            DslStmt::New {
                class_name,
                ctor_sig,
                args,
            } => self.validate_value(&DslValue::NewObject {
                class_name: class_name.clone(),
                ctor_sig: ctor_sig.clone(),
                args: args.clone(),
            })?,
            DslStmt::NewArray { array_type_name, size } => {
                let desc = java_class_to_descriptor_or_primitive(array_type_name)?;
                if !desc.starts_with('[') {
                    return Err(format!("new array requires an array type, got '{}'", array_type_name));
                }
                self.validate_value(size)?;
            }
            DslStmt::Call(stmt) => self.validate_call(stmt)?,
            DslStmt::Cast { value, class_name } => {
                self.validate_value(value)?;
                java_class_to_descriptor(class_name)?;
            }
            DslStmt::ArrayLength { array } => self.validate_value(array)?,
            DslStmt::ArrayGet {
                array,
                index,
                type_name,
            } => {
                self.validate_value(array)?;
                self.validate_value(index)?;
                if let Some(type_name) = type_name {
                    java_class_to_descriptor_or_primitive(type_name)?;
                } else if self.infer_value_descriptor(array)?.is_none() {
                    return Err("array element type cannot be inferred; use arr[index: Type]".to_string());
                }
            }
            DslStmt::ArrayPut {
                array,
                index,
                type_name,
                value,
            } => {
                self.validate_value(array)?;
                self.validate_value(index)?;
                self.validate_value(value)?;
                if let Some(type_name) = type_name {
                    java_class_to_descriptor_or_primitive(type_name)?;
                }
            }
            DslStmt::FieldRead { stmt, is_static } | DslStmt::FieldWrite { stmt, is_static } => {
                self.validate_field(stmt, *is_static)?
            }
            DslStmt::IfNull {
                value,
                invert,
                then_stmts,
                else_stmts,
            } => {
                self.validate_value(value)?;
                if *invert {
                    self.validate_stmts_with_nonnull_value(value, then_stmts)?;
                    self.validate_stmts(else_stmts)?;
                } else {
                    self.validate_stmts(then_stmts)?;
                    self.validate_stmts_with_nonnull_value(value, else_stmts)?;
                }
            }
            DslStmt::IfBool {
                value,
                then_stmts,
                else_stmts,
            } => {
                self.validate_bool_condition_value(value)?;
                self.validate_stmts(then_stmts)?;
                self.validate_stmts(else_stmts)?;
            }
            DslStmt::IfInstanceOf {
                value,
                class_name,
                then_stmts,
                else_stmts,
            } => {
                self.validate_value(value)?;
                let ty = java_class_to_descriptor(class_name)?;
                let facts = nonnull_key_for_value(value)
                    .into_iter()
                    .map(|key| (key, Some(ty.clone())))
                    .collect::<Vec<_>>();
                self.validate_with_target_facts(&facts, |ctx| ctx.validate_stmts(then_stmts))?;
                self.validate_stmts(else_stmts)?;
            }
            DslStmt::IfCmp {
                left,
                right,
                then_stmts,
                else_stmts,
                ..
            } => {
                self.validate_value(left)?;
                self.validate_value(right)?;
                self.validate_stmts(then_stmts)?;
                self.validate_stmts(else_stmts)?;
            }
            DslStmt::Switch {
                value,
                cases,
                default_stmts,
            } => {
                self.validate_value(value)?;
                for (_, stmts) in cases {
                    self.validate_stmts(stmts)?;
                }
                if let Some(stmts) = default_stmts {
                    self.validate_stmts(stmts)?;
                }
            }
            DslStmt::TryCatch {
                try_stmts,
                catch_type,
                catch_name,
                catch_stmts,
            } => {
                self.validate_stmts(try_stmts)?;
                let catch_descriptor = java_class_to_descriptor(catch_type)?;
                if !return_is_object(&catch_descriptor) {
                    return Err(format!("catch type must be an object, got {}", catch_descriptor));
                }
                if let Some(existing) = self.local_descriptors.get(catch_name) {
                    if existing != &catch_descriptor {
                        return Err(format!(
                            "catch local '{}' type mismatch: existing {}, catch {}",
                            catch_name, existing, catch_descriptor
                        ));
                    }
                } else {
                    self.local_descriptors.insert(catch_name.clone(), catch_descriptor);
                }
                self.validate_stmts(catch_stmts)?;
            }
            DslStmt::ReturnOrig { args } => self.validate_orig_args(args)?,
            DslStmt::ReturnValue { value } => {
                if let Some(value) = value {
                    self.validate_value(value)?;
                }
            }
            DslStmt::Throw { value } => {
                self.validate_value(value)?;
                if let Some(desc) = self.infer_value_descriptor(value)? {
                    if !return_is_object(&desc) {
                        return Err(format!("throw value must be an object, got {}", desc));
                    }
                }
            }
        }
        Ok(())
    }
}

pub(super) fn validate_semantics(
    env: JniEnv,
    program: &DslProgram,
    is_static: bool,
    target_type: String,
    target_params: Vec<String>,
    target_return_type: String,
) -> Result<BTreeMap<String, String>, String> {
    let mut ctx = DslSemanticContext::new(env, is_static, target_type, target_params, target_return_type);
    ctx.validate_stmts(&program.stmts)?;
    Ok(ctx.local_descriptors)
}
