use crate::ffi::hook as hook_ffi;
use crate::jsapi::java::java_fast_api::{FastConstructor, FastMethod};
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

const QUICK_PREORIG_RET_REG: usize = 16;
const FAST_STACK_VALUE_ARGS: usize = 16;

#[derive(Clone, Debug)]
enum ValueRef {
    SelfObj,
    Arg(usize),
    Orig,
    Null,
    Const(u64),
    Field {
        offset: u32,
        value_type: u8,
        object: Box<ValueRef>,
    },
    Call {
        method: Box<FastMethod>,
        receiver: Box<ValueRef>,
        args: Vec<ValueRef>,
        exact_receiver: bool,
    },
    New {
        ctor: Box<FastConstructor>,
        args: Vec<ValueRef>,
    },
}

#[derive(Clone, Debug)]
enum Condition {
    IsNull(ValueRef),
    NotNull(ValueRef),
    PtrEq(ValueRef, ValueRef),
    PtrNe(ValueRef, ValueRef),
    Always,
    Not(Box<Condition>),
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
}

#[derive(Clone, Debug)]
struct Branch {
    condition: Condition,
    ret: ValueRef,
}

#[derive(Clone, Debug)]
struct Action {
    kind: ActionKind,
}

#[derive(Clone, Debug)]
enum ActionKind {
    SetField {
        offset: u32,
        value_type: u8,
        object: ValueRef,
        value: ValueRef,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct FastRule {
    is_static: bool,
    param_count: usize,
    return_type: u8,
    object_params: Vec<bool>,
    needs_art_handle_scope: bool,
    actions: Vec<Action>,
    branches: Vec<Branch>,
    default_ret: ValueRef,
}

#[derive(Clone, Copy)]
struct FastRuleSlot {
    art_method: u64,
    rule: *const FastRule,
}

unsafe impl Send for FastRuleSlot {}
unsafe impl Sync for FastRuleSlot {}

static FAST_RULES: Mutex<Vec<FastRuleSlot>> = Mutex::new(Vec::new());
static FAST_RULES_PTR: AtomicPtr<Vec<FastRuleSlot>> = AtomicPtr::new(std::ptr::null_mut());
static FAST_CALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);
static FAST_CALLBACK_MATCHED: AtomicU64 = AtomicU64::new(0);
static FAST_CALLBACK_TOTAL_NS: AtomicU64 = AtomicU64::new(0);
static FAST_CALLBACK_MAX_NS: AtomicU64 = AtomicU64::new(0);
static FAST_CALLBACK_OVER_100US: AtomicU64 = AtomicU64::new(0);
static FAST_CALLBACK_OVER_500US: AtomicU64 = AtomicU64::new(0);
static FAST_CALLBACK_OVER_1MS: AtomicU64 = AtomicU64::new(0);
static FAST_CALLBACK_OVER_5MS: AtomicU64 = AtomicU64::new(0);
static FAST_CALLBACK_OVER_16MS: AtomicU64 = AtomicU64::new(0);
static FAST_CALLBACK_OVER_100MS: AtomicU64 = AtomicU64::new(0);
static FAST_NEW_TOTAL: AtomicU64 = AtomicU64::new(0);
static FAST_NEW_FAILED: AtomicU64 = AtomicU64::new(0);
static FAST_NEW_TOTAL_NS: AtomicU64 = AtomicU64::new(0);
static FAST_NEW_MAX_NS: AtomicU64 = AtomicU64::new(0);
static FAST_NEW_OVER_100US: AtomicU64 = AtomicU64::new(0);
static FAST_NEW_OVER_500US: AtomicU64 = AtomicU64::new(0);
static FAST_NEW_OVER_1MS: AtomicU64 = AtomicU64::new(0);
static FAST_NEW_OVER_5MS: AtomicU64 = AtomicU64::new(0);
static FAST_NEW_OVER_16MS: AtomicU64 = AtomicU64::new(0);
static FAST_NEW_OVER_100MS: AtomicU64 = AtomicU64::new(0);

#[inline]
fn update_max(target: &AtomicU64, value: u64) {
    let mut observed = target.load(Ordering::Acquire);
    while value > observed {
        match target.compare_exchange(observed, value, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(v) => observed = v,
        }
    }
}

#[inline]
fn record_latency(
    elapsed_ns: u64,
    total_ns: &AtomicU64,
    max_ns: &AtomicU64,
    over_100us: &AtomicU64,
    over_500us: &AtomicU64,
    over_1ms: &AtomicU64,
    over_5ms: &AtomicU64,
    over_16ms: &AtomicU64,
    over_100ms: &AtomicU64,
) {
    total_ns.fetch_add(elapsed_ns, Ordering::Relaxed);
    update_max(max_ns, elapsed_ns);
    if elapsed_ns >= 100_000 {
        over_100us.fetch_add(1, Ordering::Relaxed);
    }
    if elapsed_ns >= 500_000 {
        over_500us.fetch_add(1, Ordering::Relaxed);
    }
    if elapsed_ns >= 1_000_000 {
        over_1ms.fetch_add(1, Ordering::Relaxed);
    }
    if elapsed_ns >= 5_000_000 {
        over_5ms.fetch_add(1, Ordering::Relaxed);
    }
    if elapsed_ns >= 16_000_000 {
        over_16ms.fetch_add(1, Ordering::Relaxed);
    }
    if elapsed_ns >= 100_000_000 {
        over_100ms.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
fn record_callback_latency(elapsed_ns: u64) {
    record_latency(
        elapsed_ns,
        &FAST_CALLBACK_TOTAL_NS,
        &FAST_CALLBACK_MAX_NS,
        &FAST_CALLBACK_OVER_100US,
        &FAST_CALLBACK_OVER_500US,
        &FAST_CALLBACK_OVER_1MS,
        &FAST_CALLBACK_OVER_5MS,
        &FAST_CALLBACK_OVER_16MS,
        &FAST_CALLBACK_OVER_100MS,
    );
}

#[inline]
fn record_new_latency(elapsed_ns: u64) {
    record_latency(
        elapsed_ns,
        &FAST_NEW_TOTAL_NS,
        &FAST_NEW_MAX_NS,
        &FAST_NEW_OVER_100US,
        &FAST_NEW_OVER_500US,
        &FAST_NEW_OVER_1MS,
        &FAST_NEW_OVER_5MS,
        &FAST_NEW_OVER_16MS,
        &FAST_NEW_OVER_100MS,
    );
}

pub(crate) fn register_fast_rule(art_method: u64, rule: FastRule) {
    let rule_ptr = Box::into_raw(Box::new(rule));
    let mut rules = FAST_RULES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(slot) = rules.iter_mut().find(|s| s.art_method == art_method) {
        slot.rule = rule_ptr;
    } else {
        rules.push(FastRuleSlot {
            art_method,
            rule: rule_ptr,
        });
    }
    rules.sort_unstable_by_key(|s| s.art_method);
    let new_snapshot = Box::new(rules.clone());
    let old = FAST_RULES_PTR.swap(Box::into_raw(new_snapshot), Ordering::Release);
    if !old.is_null() {
        let old_usize = old as usize;
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            unsafe {
                drop(Box::from_raw(old_usize as *mut Vec<FastRuleSlot>));
            }
        });
    }
}

pub(crate) fn is_fast_hook(art_method: u64) -> bool {
    unsafe { find_rule(art_method).is_some() }
}

pub(crate) fn compile_fast_rule(
    dsl: &str,
    is_static: bool,
    param_types: Vec<String>,
    return_type: u8,
) -> Result<FastRule, String> {
    let param_count = param_types.len();
    let object_params = param_types
        .iter()
        .map(|sig| sig.starts_with('L') || sig.starts_with('['))
        .collect::<Vec<_>>();
    let mut actions = Vec::new();
    let mut branches = Vec::new();
    let mut default_ret = None;
    let statements = split_js_statements(dsl)?;

    let mut i = 0;
    while i < statements.len() {
        let line = statements[i].trim();
        if line == "return" {
            default_ret = Some(ValueRef::Null);
            i += 1;
            continue;
        }
        if let Some(rest) = line.strip_prefix("return ") {
            default_ret = Some(parse_value_ref(rest.trim())?);
            i += 1;
            continue;
        }

        if let Some(action) = parse_action(line)? {
            actions.push(action);
            i += 1;
            continue;
        }

        if starts_word(line, 0, "if") {
            let (condition, ret, else_ret) = parse_js_if_return(line)?;
            branches.push(Branch { condition, ret });
            if let Some(ret) = else_ret {
                default_ret = Some(ret);
            }
            i += 1;
            continue;
        }

        return Err(format!("unsupported fastHook statement: {}", line));
    }

    let needs_art_handle_scope = actions.iter().any(action_needs_art_handle_scope)
        || branches.iter().any(branch_needs_art_handle_scope)
        || value_needs_art_handle_scope(&default_ret.clone().unwrap_or(ValueRef::Orig));

    Ok(FastRule {
        is_static,
        param_count,
        return_type,
        object_params,
        needs_art_handle_scope,
        actions,
        branches,
        default_ret: default_ret.unwrap_or(ValueRef::Orig),
    })
}

fn action_needs_art_handle_scope(action: &Action) -> bool {
    match &action.kind {
        ActionKind::SetField { object, value, .. } => {
            value_needs_art_handle_scope(object) || value_needs_art_handle_scope(value)
        }
    }
}

fn branch_needs_art_handle_scope(branch: &Branch) -> bool {
    condition_needs_art_handle_scope(&branch.condition) || value_needs_art_handle_scope(&branch.ret)
}

fn condition_needs_art_handle_scope(condition: &Condition) -> bool {
    match condition {
        Condition::IsNull(value) | Condition::NotNull(value) => value_needs_art_handle_scope(value),
        Condition::PtrEq(left, right) | Condition::PtrNe(left, right) => {
            value_needs_art_handle_scope(left) || value_needs_art_handle_scope(right)
        }
        Condition::Always => false,
        Condition::Not(inner) => condition_needs_art_handle_scope(inner),
        Condition::And(left, right) | Condition::Or(left, right) => {
            condition_needs_art_handle_scope(left) || condition_needs_art_handle_scope(right)
        }
    }
}

fn value_needs_art_handle_scope(value: &ValueRef) -> bool {
    match value {
        ValueRef::New { .. } => true,
        ValueRef::Field { object, .. } => value_needs_art_handle_scope(object),
        ValueRef::Call { receiver, args, .. } => {
            value_needs_art_handle_scope(receiver) || args.iter().any(value_needs_art_handle_scope)
        }
        ValueRef::SelfObj | ValueRef::Arg(_) | ValueRef::Orig | ValueRef::Null | ValueRef::Const(_) => false,
    }
}

fn split_js_statements(dsl: &str) -> Result<Vec<String>, String> {
    let mut src = String::new();
    for raw_line in dsl.lines() {
        let mut line = raw_line;
        if let Some(pos) = line.find("//") {
            line = &line[..pos];
        }
        src.push_str(line);
        src.push('\n');
    }

    let mut statements = Vec::new();
    let mut i = 0usize;
    while i < src.len() {
        i = skip_ws_and_semis(&src, i);
        if i >= src.len() {
            break;
        }

        if starts_word(&src, i, "if") {
            let start = i;
            i += 2;
            i = skip_ws(&src, i);
            if !src[i..].starts_with('(') {
                return Err(format!(
                    "fastHook if requires parentheses near: {}",
                    &src[start..].trim()
                ));
            }
            let cond_close = find_matching_paren(&src[i + 1..])
                .ok_or_else(|| format!("fastHook if missing ): {}", &src[start..].trim()))?;
            i += 1 + cond_close + 1;
            i = consume_js_return_body(&src, i)?;
            let after_then = skip_ws_and_semis(&src, i);
            if starts_word(&src, after_then, "else") {
                i = consume_js_return_body(&src, after_then + 4)?;
            }
            statements.push(src[start..i].trim().trim_end_matches(';').trim().to_string());
            continue;
        }

        let start = i;
        while i < src.len() && !src[i..].starts_with(';') {
            let ch = src[i..].chars().next().unwrap();
            i += ch.len_utf8();
        }
        let text = src[start..i].trim();
        if !text.is_empty() {
            statements.push(text.to_string());
        }
    }

    Ok(statements)
}

fn skip_ws(text: &str, mut i: usize) -> usize {
    while i < text.len() {
        let ch = text[i..].chars().next().unwrap();
        if !ch.is_whitespace() {
            break;
        }
        i += ch.len_utf8();
    }
    i
}

fn skip_ws_and_semis(text: &str, mut i: usize) -> usize {
    while i < text.len() {
        let ch = text[i..].chars().next().unwrap();
        if !(ch.is_whitespace() || ch == ';') {
            break;
        }
        i += ch.len_utf8();
    }
    i
}

fn starts_word(text: &str, i: usize, word: &str) -> bool {
    if !text[i..].starts_with(word) {
        return false;
    }
    let before_ok = i == 0 || !is_ident_byte(text.as_bytes()[i - 1]);
    let end = i + word.len();
    let after_ok = end >= text.len() || !is_ident_byte(text.as_bytes()[end]);
    before_ok && after_ok
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn consume_js_return_body(text: &str, mut i: usize) -> Result<usize, String> {
    i = skip_ws(text, i);
    if i >= text.len() {
        return Err("fastHook statement missing body".to_string());
    }
    if text[i..].starts_with('{') {
        let close = find_matching_brace(&text[i + 1..]).ok_or_else(|| "fastHook block missing }".to_string())?;
        Ok(i + 1 + close + 1)
    } else {
        while i < text.len() && !text[i..].starts_with(';') && !starts_word(text, i, "else") {
            let ch = text[i..].chars().next().unwrap();
            i += ch.len_utf8();
        }
        if i < text.len() && text[i..].starts_with(';') {
            i += 1;
        }
        Ok(i)
    }
}

fn parse_js_if_return(text: &str) -> Result<(Condition, ValueRef, Option<ValueRef>), String> {
    let text = text.trim();
    let Some(rest) = text.strip_prefix("if") else {
        return Err(format!("fastHook if must start with if: {}", text));
    };
    let rest = rest.trim_start();
    let Some(after_open) = rest.strip_prefix('(') else {
        return Err(format!("fastHook if requires parentheses: {}", text));
    };
    let close = find_matching_paren(after_open).ok_or_else(|| format!("fastHook if missing ): {}", text))?;
    let condition = parse_condition(&after_open[..close])?;
    let rest = after_open[close + 1..].trim();
    let (body, else_body) = split_else(rest)?;
    let ret = parse_return_body(body, text)?;
    let else_ret = match else_body {
        Some(body) => Some(parse_return_body(body, text)?),
        None => None,
    };
    Ok((condition, ret, else_ret))
}

fn find_matching_paren(text_after_open: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (idx, ch) in text_after_open.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' if depth == 0 => return Some(idx),
            ')' => depth -= 1,
            _ => {}
        }
    }
    None
}

fn split_else(text: &str) -> Result<(&str, Option<&str>), String> {
    let text = text.trim();
    if let Some(stripped) = text.strip_prefix('{') {
        let close = find_matching_brace(stripped).ok_or_else(|| format!("fastHook if block missing }}: {}", text))?;
        let body = stripped[..close].trim();
        let after = stripped[close + 1..].trim();
        if after.is_empty() {
            return Ok((body, None));
        }
        let Some(else_body) = after.strip_prefix("else") else {
            return Err(format!("unsupported fastHook text after if block: {}", after));
        };
        Ok((body, Some(trim_js_block(else_body.trim())?)))
    } else if let Some((body, else_body)) = split_top_level(text, "else") {
        Ok((body, Some(trim_js_block(else_body)?)))
    } else {
        Ok((text, None))
    }
}

fn find_matching_brace(text_after_open: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (idx, ch) in text_after_open.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' if depth == 0 => return Some(idx),
            '}' => depth -= 1,
            _ => {}
        }
    }
    None
}

fn trim_js_block(text: &str) -> Result<&str, String> {
    let text = text.trim();
    if let Some(stripped) = text.strip_prefix('{') {
        stripped
            .strip_suffix('}')
            .map(str::trim)
            .ok_or_else(|| format!("fastHook block missing }}: {}", text))
    } else {
        Ok(text)
    }
}

fn parse_return_body(body: &str, original: &str) -> Result<ValueRef, String> {
    let body = body.trim().trim_end_matches(';').trim();
    let Some(ret_text) = body.strip_prefix("return ") else {
        if body == "return" {
            return Ok(ValueRef::Null);
        }
        return Err(format!("fastHook if body must be return statement: {}", original));
    };
    parse_value_ref(ret_text.trim())
}

fn parse_action(text: &str) -> Result<Option<Action>, String> {
    let text = text.trim().trim_end_matches(';').trim();
    let Some(inner) = strip_call(text, "setField") else {
        return Ok(None);
    };
    let args = split_top_level_args(inner)?;
    if args.len() != 3 {
        return Err(format!("setField() requires 3 args: {}", text));
    }
    let field = parse_field_ref(args[0], args[1])?;
    let value = parse_value_ref(args[2])?;
    let ValueRef::Field {
        offset,
        value_type,
        object,
    } = field
    else {
        return Err(format!("invalid setField target: {}", text));
    };
    Ok(Some(Action {
        kind: ActionKind::SetField {
            offset,
            value_type,
            object: *object,
            value,
        },
    }))
}

fn parse_condition(text: &str) -> Result<Condition, String> {
    let text = trim_outer_parens(text.trim());
    if text == "true" {
        return Ok(Condition::Always);
    }
    if text == "false" {
        return Ok(Condition::Not(Box::new(Condition::Always)));
    }
    if let Some((lhs, rhs)) = split_top_level(text, "||") {
        return Ok(Condition::Or(
            Box::new(parse_condition(lhs)?),
            Box::new(parse_condition(rhs)?),
        ));
    }
    if let Some((lhs, rhs)) = split_top_level(text, "&&") {
        return Ok(Condition::And(
            Box::new(parse_condition(lhs)?),
            Box::new(parse_condition(rhs)?),
        ));
    }
    if let Some(rest) = text.strip_prefix('!') {
        return Ok(Condition::Not(Box::new(parse_condition(rest)?)));
    }
    if let Some((lhs, rhs)) = split_top_level(text, "!==").or_else(|| split_top_level(text, "!=")) {
        let lhs = parse_value_ref(lhs)?;
        let rhs = parse_value_ref(rhs)?;
        if matches!(rhs, ValueRef::Null) {
            Ok(Condition::NotNull(lhs))
        } else if matches!(lhs, ValueRef::Null) {
            Ok(Condition::NotNull(rhs))
        } else {
            Ok(Condition::PtrNe(lhs, rhs))
        }
    } else if let Some((lhs, rhs)) = split_top_level(text, "===").or_else(|| split_top_level(text, "==")) {
        let lhs = parse_value_ref(lhs)?;
        let rhs = parse_value_ref(rhs)?;
        if matches!(rhs, ValueRef::Null) {
            Ok(Condition::IsNull(lhs))
        } else if matches!(lhs, ValueRef::Null) {
            Ok(Condition::IsNull(rhs))
        } else {
            Ok(Condition::PtrEq(lhs, rhs))
        }
    } else {
        let value = parse_value_ref(text)?;
        if matches!(value, ValueRef::Null | ValueRef::Const(0)) {
            Ok(Condition::Not(Box::new(Condition::Always)))
        } else {
            Ok(Condition::NotNull(value))
        }
    }
}

fn trim_outer_parens(mut text: &str) -> &str {
    loop {
        let t = text.trim();
        if t.starts_with('(') && t.ends_with(')') {
            let inner = &t[1..t.len() - 1];
            if split_top_level_parens_balanced(inner) {
                text = inner;
                continue;
            }
        }
        return t;
    }
}

fn split_top_level_parens_balanced(text: &str) -> bool {
    let mut depth = 0i32;
    for ch in text.chars() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

fn split_top_level<'a>(text: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    let mut depth = 0i32;
    let mut i = 0usize;
    while i + op.len() <= text.len() {
        let ch = text[i..].chars().next()?;
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && text[i..].starts_with(op) {
            return Some((text[..i].trim(), text[i + op.len()..].trim()));
        }
        i += ch.len_utf8();
    }
    None
}

fn parse_value_ref(text: &str) -> Result<ValueRef, String> {
    let text = text.trim().trim_end_matches(';');
    if let Some(inner) = strip_call(text, "field") {
        let args = split_top_level_args(inner)?;
        if args.len() != 2 {
            return Err(format!("field() requires 2 args: {}", text));
        }
        return parse_field_ref(args[0], args[1]);
    }
    if let Some(inner) = strip_call(text, "call").or_else(|| strip_call(text, "jcall")) {
        return parse_call_ref(inner, true);
    }
    if let Some(inner) = strip_call(text, "directCall") {
        return parse_call_ref(inner, false);
    }
    if let Some(inner) = strip_call(text, "$new").or_else(|| strip_call(text, "jnew")) {
        return parse_new_ref(inner);
    }
    match text {
        "this" => Ok(ValueRef::SelfObj),
        "orig" => Ok(ValueRef::Orig),
        "null" => Ok(ValueRef::Null),
        "false" => Ok(ValueRef::Const(0)),
        "true" => Ok(ValueRef::Const(1)),
        _ if text.starts_with("args[") && text.ends_with(']') => {
            let idx = text[5..text.len() - 1]
                .trim()
                .parse::<usize>()
                .map_err(|_| format!("invalid fastHook args reference: {}", text))?;
            Ok(ValueRef::Arg(idx))
        }
        _ if text.starts_with("arguments[") && text.ends_with(']') => {
            let idx = text[10..text.len() - 1]
                .trim()
                .parse::<usize>()
                .map_err(|_| format!("invalid fastHook arguments reference: {}", text))?;
            Ok(ValueRef::Arg(idx))
        }
        _ => parse_u64_literal(text)
            .map(ValueRef::Const)
            .ok_or_else(|| format!("unsupported fastHook value: {}", text)),
    }
}

fn parse_call_ref(inner: &str, exact_receiver: bool) -> Result<ValueRef, String> {
    let args = split_top_level_args(inner)?;
    if args.is_empty() {
        return Err("call() requires a method handle".to_string());
    }
    let handle = parse_u64_literal(args[0]).ok_or_else(|| {
        format!(
            "method handle must be a numeric literal created by Java.fastMethod(): {}",
            args[0]
        )
    })?;
    let Some(method) = crate::jsapi::java::java_fast_api::get_fast_method(handle) else {
        return Err(format!("unknown fast method handle: {}", handle));
    };

    let mut next = 1usize;
    let receiver = if method.is_static {
        ValueRef::Null
    } else {
        if args.len() < 2 {
            return Err("call() instance method requires receiver".to_string());
        }
        next = 2;
        parse_value_ref(args[1])?
    };
    let expected = method.param_types.len();
    let actual = args.len().saturating_sub(next);
    if actual != expected {
        return Err(format!(
            "call() argument count mismatch: expected {}, got {}",
            expected, actual
        ));
    }

    let mut call_args = Vec::with_capacity(expected);
    for arg in &args[next..] {
        call_args.push(parse_value_ref(arg)?);
    }
    Ok(ValueRef::Call {
        method: Box::new(method),
        receiver: Box::new(receiver),
        args: call_args,
        exact_receiver,
    })
}

fn parse_new_ref(inner: &str) -> Result<ValueRef, String> {
    let args = split_top_level_args(inner)?;
    if args.is_empty() {
        return Err("$new() requires a constructor handle".to_string());
    }
    let handle = parse_u64_literal(args[0]).ok_or_else(|| {
        format!(
            "constructor handle must be a numeric literal created by Java.fastConstructor(): {}",
            args[0]
        )
    })?;
    let Some(ctor) = crate::jsapi::java::java_fast_api::get_fast_constructor(handle) else {
        return Err(format!("unknown fast constructor handle: {}", handle));
    };
    let expected = ctor.param_types.len();
    let actual = args.len().saturating_sub(1);
    if actual != expected {
        return Err(format!(
            "$new() argument count mismatch: expected {}, got {}",
            expected, actual
        ));
    }

    let mut ctor_args = Vec::with_capacity(expected);
    for arg in &args[1..] {
        ctor_args.push(parse_value_ref(arg)?);
    }
    Ok(ValueRef::New {
        ctor: Box::new(ctor),
        args: ctor_args,
    })
}

fn strip_call<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(name)?;
    let rest = rest.trim_start();
    if !rest.starts_with('(') || !rest.ends_with(')') {
        return None;
    }
    Some(&rest[1..rest.len() - 1])
}

fn split_top_level_args(text: &str) -> Result<Vec<&str>, String> {
    let mut args = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, ch) in text.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return Err(format!("unbalanced call args: {}", text));
                }
            }
            ',' if depth == 0 => {
                args.push(text[start..i].trim());
                start = i + ch.len_utf8();
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(format!("unbalanced call args: {}", text));
    }
    let tail = text[start..].trim();
    if !tail.is_empty() {
        args.push(tail);
    }
    Ok(args)
}

fn parse_field_ref(handle_text: &str, object_text: &str) -> Result<ValueRef, String> {
    let handle = parse_u64_literal(handle_text).ok_or_else(|| {
        format!(
            "field handle must be a numeric literal created by Java.fastField(): {}",
            handle_text
        )
    })?;
    let Some(field) = crate::jsapi::java::java_fast_api::get_fast_field(handle) else {
        return Err(format!("unknown fast field handle: {}", handle));
    };
    if field.is_static {
        return Err("fastHook field() only supports instance fields".to_string());
    }
    let object = parse_value_ref(object_text)?;
    Ok(ValueRef::Field {
        offset: field.offset,
        value_type: field.value_type,
        object: Box::new(object),
    })
}

fn parse_u64_literal(text: &str) -> Option<u64> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    text.parse::<u64>().ok()
}

#[inline]
unsafe fn find_rule(art_method: u64) -> Option<&'static FastRule> {
    let ptr = FAST_RULES_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    let slots = &*ptr;
    slots
        .binary_search_by_key(&art_method, |s| s.art_method)
        .ok()
        .and_then(|idx| slots.get(idx))
        .and_then(|slot| slot.rule.as_ref())
}

#[inline]
unsafe fn read_arg(ctx: &hook_ffi::HookContext, rule: &FastRule, idx: usize) -> u64 {
    if idx >= rule.param_count {
        return 0;
    }
    let gp_index = if rule.is_static { 1 + idx } else { 2 + idx };
    if gp_index < 8 {
        ctx.x[gp_index]
    } else {
        let sp = ctx.sp as usize;
        *((sp + (gp_index - 8) * 8) as *const u64)
    }
}

#[inline]
unsafe fn read_value(ctx: &hook_ffi::HookContext, rule: &FastRule, value: &ValueRef) -> u64 {
    match value {
        ValueRef::SelfObj => {
            if rule.is_static {
                0
            } else {
                ctx.x[1]
            }
        }
        ValueRef::Arg(idx) => read_arg(ctx, rule, *idx),
        ValueRef::Orig => match rule.return_type {
            b'F' | b'D' => ctx.d[0],
            _ => ctx.x[QUICK_PREORIG_RET_REG],
        },
        ValueRef::Null => 0,
        ValueRef::Const(v) => *v,
        ValueRef::Field {
            offset,
            value_type,
            object,
        } => {
            let obj = read_value(ctx, rule, object);
            read_instance_field(obj, *offset, *value_type).unwrap_or(0)
        }
        ValueRef::Call {
            method,
            receiver,
            args,
            exact_receiver,
        } => {
            let recv = if method.is_static {
                0
            } else {
                read_value(ctx, rule, receiver)
            };
            if *exact_receiver && !crate::jsapi::java::java_fast_api::fast_method_receiver_is_exact(method, recv) {
                return 0;
            }
            service_quick_suspend(ctx);
            let ret = with_raw_value_args(ctx, rule, args, |raw_args| {
                crate::jsapi::java::java_fast_api::invoke_fast_method_raw_on_thread(method, ctx.x[19], recv, raw_args)
            })
            .unwrap_or(0);
            service_quick_suspend(ctx);
            ret
        }
        ValueRef::New { ctor, args } => {
            let start = std::time::Instant::now();
            FAST_NEW_TOTAL.fetch_add(1, Ordering::Relaxed);
            let thread = ctx.x[19];
            service_quick_suspend(ctx);
            let Some(obj) =
                crate::jsapi::java::java_fast_api::alloc_fast_object_quick_on_thread(thread, ctor.class_mirror)
            else {
                FAST_NEW_FAILED.fetch_add(1, Ordering::Relaxed);
                let elapsed = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
                record_new_latency(elapsed);
                return 0;
            };
            let root = match crate::jsapi::java::java_fast_api::root_fast_raw_object_for_callback(obj) {
                Ok(root) => root,
                _ => {
                    FAST_NEW_FAILED.fetch_add(1, Ordering::Relaxed);
                    let elapsed = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
                    record_new_latency(elapsed);
                    return 0;
                }
            };
            let mut ctor_raw_stack = [0u64; FAST_STACK_VALUE_ARGS];
            let ctor_args = match build_raw_value_args(ctx, rule, args, &mut ctor_raw_stack) {
                Some(v) => v,
                None => {
                    FAST_NEW_FAILED.fetch_add(1, Ordering::Relaxed);
                    let elapsed = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
                    record_new_latency(elapsed);
                    return 0;
                }
            };
            let obj = crate::jsapi::java::java_fast_api::read_fast_art_root(root).unwrap_or(obj);
            let ret = match crate::jsapi::java::java_fast_api::invoke_fast_constructor_raw_on_thread(
                ctor, thread, obj, &ctor_args,
            ) {
                Ok(()) => crate::jsapi::java::java_fast_api::read_fast_art_root(root).unwrap_or(obj),
                Err(_) => {
                    FAST_NEW_FAILED.fetch_add(1, Ordering::Relaxed);
                    0
                }
            };
            service_quick_suspend(ctx);
            let elapsed = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            record_new_latency(elapsed);
            ret
        }
    }
}

#[inline]
unsafe fn service_quick_suspend(ctx: &hook_ffi::HookContext) {
    let _ = ctx;
}

#[inline]
unsafe fn with_raw_value_args<R>(
    ctx: &hook_ffi::HookContext,
    rule: &FastRule,
    values: &[ValueRef],
    f: impl FnOnce(&[u64]) -> Result<R, String>,
) -> Result<R, String> {
    let mut stack = [0u64; FAST_STACK_VALUE_ARGS];
    let Some(raw_args) = build_raw_value_args(ctx, rule, values, &mut stack) else {
        return Err("fastHook argument buffer exceeded fast stack capacity".to_string());
    };
    f(raw_args)
}

#[inline]
unsafe fn build_raw_value_args<'a>(
    ctx: &hook_ffi::HookContext,
    rule: &FastRule,
    values: &[ValueRef],
    out: &'a mut [u64; FAST_STACK_VALUE_ARGS],
) -> Option<&'a [u64]> {
    if values.len() > out.len() {
        return None;
    }
    for (i, value) in values.iter().enumerate() {
        out[i] = read_value(ctx, rule, value);
    }
    Some(&out[..values.len()])
}

#[inline]
unsafe fn root_fast_hook_entry_refs(ctx: &hook_ffi::HookContext, rule: &FastRule) {
    if !rule.is_static && ctx.x[1] != 0 {
        let _ = crate::jsapi::java::java_fast_api::root_fast_raw_object_for_callback(ctx.x[1]);
    }
    for (idx, is_object) in rule.object_params.iter().enumerate() {
        if !*is_object {
            continue;
        }
        let raw = read_arg(ctx, rule, idx);
        if raw != 0 {
            let _ = crate::jsapi::java::java_fast_api::root_fast_raw_object_for_callback(raw);
        }
    }
}

#[inline]
unsafe fn condition_matches(ctx: &hook_ffi::HookContext, rule: &FastRule, condition: &Condition) -> bool {
    match condition {
        Condition::Always => true,
        Condition::IsNull(v) => read_value(ctx, rule, v) == 0,
        Condition::NotNull(v) => read_value(ctx, rule, v) != 0,
        Condition::PtrEq(a, b) => read_value(ctx, rule, a) == read_value(ctx, rule, b),
        Condition::PtrNe(a, b) => read_value(ctx, rule, a) != read_value(ctx, rule, b),
        Condition::Not(c) => !condition_matches(ctx, rule, c),
        Condition::And(a, b) => condition_matches(ctx, rule, a) && condition_matches(ctx, rule, b),
        Condition::Or(a, b) => condition_matches(ctx, rule, a) || condition_matches(ctx, rule, b),
    }
}

#[inline]
unsafe fn execute_action(ctx: &hook_ffi::HookContext, rule: &FastRule, action: &Action) {
    match &action.kind {
        ActionKind::SetField {
            offset,
            value_type,
            object,
            value,
        } => {
            let obj = read_value(ctx, rule, object);
            let raw = read_value(ctx, rule, value);
            let thread = ctx.x[19];
            let _ = write_instance_field(thread, obj, *offset, *value_type, raw);
        }
    }
}

#[inline]
unsafe fn read_instance_field(obj: u64, offset: u32, value_type: u8) -> Option<u64> {
    if obj == 0 || offset == 0 {
        return None;
    }
    let addr = obj.checked_add(offset as u64)?;
    Some(match value_type {
        b'Z' => (std::ptr::read_volatile(addr as *const u8) != 0) as u64,
        b'B' => std::ptr::read_volatile(addr as *const i8) as u64,
        b'C' => std::ptr::read_volatile(addr as *const u16) as u64,
        b'S' => std::ptr::read_volatile(addr as *const i16) as u64,
        b'I' => std::ptr::read_volatile(addr as *const i32) as u64,
        b'J' => std::ptr::read_volatile(addr as *const i64) as u64,
        b'F' => std::ptr::read_volatile(addr as *const u32) as u64,
        b'D' => std::ptr::read_volatile(addr as *const u64),
        b'L' | b'[' => std::ptr::read_volatile(addr as *const u32) as u64,
        _ => return None,
    })
}

#[inline]
unsafe fn write_instance_field(thread: u64, obj: u64, offset: u32, value_type: u8, raw: u64) -> Option<()> {
    if obj == 0 || offset == 0 {
        return None;
    }
    let addr = obj.checked_add(offset as u64)?;
    match value_type {
        b'Z' => std::ptr::write_volatile(addr as *mut u8, if raw != 0 { 1 } else { 0 }),
        b'B' => std::ptr::write_volatile(addr as *mut i8, raw as i8),
        b'C' => std::ptr::write_volatile(addr as *mut u16, raw as u16),
        b'S' => std::ptr::write_volatile(addr as *mut i16, raw as i16),
        b'I' => std::ptr::write_volatile(addr as *mut i32, raw as i32),
        b'J' => std::ptr::write_volatile(addr as *mut i64, raw as i64),
        b'F' => std::ptr::write_volatile(addr as *mut u32, raw as u32),
        b'D' => std::ptr::write_volatile(addr as *mut u64, raw),
        b'L' | b'[' => {
            std::ptr::write_volatile(addr as *mut u32, raw as u32);
            if raw != 0 {
                mark_card(thread, obj)?;
            }
        }
        _ => return None,
    }
    Some(())
}

#[inline]
unsafe fn mark_card(thread: u64, holder: u64) -> Option<()> {
    const ART_CARD_SHIFT: u64 = 10;
    const ART_CARD_DIRTY: u8 = 0x70;
    if thread == 0 || holder == 0 {
        return None;
    }
    let card_table = std::ptr::read_volatile((thread as usize + 0x90) as *const u64);
    if card_table == 0 {
        return None;
    }
    let card = card_table.checked_add(holder >> ART_CARD_SHIFT)?;
    std::ptr::write_volatile(card as *mut u8, ART_CARD_DIRTY);
    Some(())
}

#[inline]
unsafe fn write_return(ctx: *mut hook_ffi::HookContext, rule: &FastRule, raw: u64) {
    if rule.return_type == b'V' {
        (*ctx).intercept_leave = 1;
        return;
    }
    if matches!(rule.return_type, b'F' | b'D') {
        (*ctx).d[0] = raw;
    } else {
        (*ctx).x[0] = raw;
    }
    (*ctx).intercept_leave = 1;
}

pub unsafe extern "C" fn fast_hook_dispatch_from_quick(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    let start = std::time::Instant::now();
    FAST_CALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed);

    let art_method = user_data as u64;
    let Some(rule) = find_rule(art_method) else {
        return;
    };

    if rule.needs_art_handle_scope {
        crate::jsapi::java::java_fast_api::with_fast_art_handle_scope((*ctx_ptr).x[19], || {
            let ctx = &*ctx_ptr;
            root_fast_hook_entry_refs(ctx, rule);
            run_fast_rule_body(ctx_ptr, rule);
        });
    } else {
        run_fast_rule_body(ctx_ptr, rule);
    }
    let elapsed = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    record_callback_latency(elapsed);
}

#[inline]
unsafe fn run_fast_rule_body(ctx_ptr: *mut hook_ffi::HookContext, rule: &FastRule) {
    let ctx = &*ctx_ptr;
    for action in &rule.actions {
        execute_action(ctx, rule, action);
    }

    let mut ret = &rule.default_ret;
    for branch in &rule.branches {
        if condition_matches(ctx, rule, &branch.condition) {
            ret = &branch.ret;
            FAST_CALLBACK_MATCHED.fetch_add(1, Ordering::Relaxed);
            break;
        }
    }

    let raw = read_value(ctx, rule, ret);
    write_return(ctx_ptr, rule, raw);
}

pub(crate) struct FastStats {
    pub(crate) total: u64,
    pub(crate) matched: u64,
    pub(crate) total_ns: u64,
    pub(crate) max_ns: u64,
    pub(crate) over_100us: u64,
    pub(crate) over_500us: u64,
    pub(crate) over_1ms: u64,
    pub(crate) over_5ms: u64,
    pub(crate) over_16ms: u64,
    pub(crate) over_100ms: u64,
    pub(crate) new_total: u64,
    pub(crate) new_failed: u64,
    pub(crate) new_total_ns: u64,
    pub(crate) new_max_ns: u64,
    pub(crate) new_over_100us: u64,
    pub(crate) new_over_500us: u64,
    pub(crate) new_over_1ms: u64,
    pub(crate) new_over_5ms: u64,
    pub(crate) new_over_16ms: u64,
    pub(crate) new_over_100ms: u64,
    pub(crate) new_tlab_hit: u64,
    pub(crate) new_tlab_miss: u64,
    pub(crate) new_slow_path: u64,
}

pub(crate) fn fast_stats() -> FastStats {
    let (new_tlab_hit, new_tlab_miss, new_slow_path) =
        unsafe { crate::jsapi::java::java_fast_api::fast_tlab_alloc_stats() };
    FastStats {
        total: FAST_CALLBACK_TOTAL.load(Ordering::Acquire),
        matched: FAST_CALLBACK_MATCHED.load(Ordering::Acquire),
        total_ns: FAST_CALLBACK_TOTAL_NS.load(Ordering::Acquire),
        max_ns: FAST_CALLBACK_MAX_NS.load(Ordering::Acquire),
        over_100us: FAST_CALLBACK_OVER_100US.load(Ordering::Acquire),
        over_500us: FAST_CALLBACK_OVER_500US.load(Ordering::Acquire),
        over_1ms: FAST_CALLBACK_OVER_1MS.load(Ordering::Acquire),
        over_5ms: FAST_CALLBACK_OVER_5MS.load(Ordering::Acquire),
        over_16ms: FAST_CALLBACK_OVER_16MS.load(Ordering::Acquire),
        over_100ms: FAST_CALLBACK_OVER_100MS.load(Ordering::Acquire),
        new_total: FAST_NEW_TOTAL.load(Ordering::Acquire),
        new_failed: FAST_NEW_FAILED.load(Ordering::Acquire),
        new_total_ns: FAST_NEW_TOTAL_NS.load(Ordering::Acquire),
        new_max_ns: FAST_NEW_MAX_NS.load(Ordering::Acquire),
        new_over_100us: FAST_NEW_OVER_100US.load(Ordering::Acquire),
        new_over_500us: FAST_NEW_OVER_500US.load(Ordering::Acquire),
        new_over_1ms: FAST_NEW_OVER_1MS.load(Ordering::Acquire),
        new_over_5ms: FAST_NEW_OVER_5MS.load(Ordering::Acquire),
        new_over_16ms: FAST_NEW_OVER_16MS.load(Ordering::Acquire),
        new_over_100ms: FAST_NEW_OVER_100MS.load(Ordering::Acquire),
        new_tlab_hit,
        new_tlab_miss,
        new_slow_path,
    }
}
