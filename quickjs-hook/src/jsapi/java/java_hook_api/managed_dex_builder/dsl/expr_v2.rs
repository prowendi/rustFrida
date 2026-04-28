use super::*;
use std::collections::BTreeMap;
use token_stream::DslTokenStream;

const V2_INT_BINARY_TOKEN_OPS: &[(&str, DslIntBinOp, u8)] = &[
    (">>>", DslIntBinOp::Ushr, 5),
    ("<<", DslIntBinOp::Shl, 5),
    (">>", DslIntBinOp::Shr, 5),
];

const V2_INT_BINARY_CHAR_OPS: &[(char, DslIntBinOp, u8)] = &[
    ('|', DslIntBinOp::Or, 1),
    ('^', DslIntBinOp::Xor, 2),
    ('&', DslIntBinOp::And, 3),
    ('+', DslIntBinOp::Add, 6),
    ('-', DslIntBinOp::Sub, 6),
    ('*', DslIntBinOp::Mul, 7),
    ('/', DslIntBinOp::Div, 7),
    ('%', DslIntBinOp::Rem, 7),
];

impl<'a> DslParser<'a> {
    pub(super) fn try_parse_expr_v2(&mut self) -> Option<DslValue> {
        let start = self.pos;
        let mut stream = DslTokenStream::new(self.input, &self.tokens, self.pos);
        let value = parse_v2_int_binary_expr(&mut stream, &self.local_scopes, 0).ok()?;
        if has_v2_unsupported_trailing_token(&stream) {
            self.pos = start;
            return None;
        }
        self.pos = stream.pos();
        Some(value)
    }
}

fn parse_v2_int_binary_expr(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
    min_prec: u8,
) -> Result<DslValue, String> {
    let mut left = parse_v2_unary_expr(stream, local_scopes)?;
    loop {
        let Some((op, prec)) = peek_v2_int_binary_op(stream) else {
            break;
        };
        if prec < min_prec {
            break;
        }
        consume_v2_int_binary_op(stream, op)?;
        let right = parse_v2_int_binary_expr(stream, local_scopes, prec + 1)?;
        left = fold_int_binop(op, left, right);
    }
    Ok(left)
}

fn parse_v2_unary_expr(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslValue, String> {
    if stream.consume_char('-') {
        if matches!(stream.current_kind(), Some(DslTokenKind::Number(_))) {
            return Ok(DslValue::Int(stream.parse_i16_after_sign(true)?));
        }
        let value = parse_v2_unary_expr(stream, local_scopes)?;
        return Ok(fold_unary_op(DslUnaryOp::Neg, value));
    }
    if stream.consume_char('~') {
        let value = parse_v2_unary_expr(stream, local_scopes)?;
        return Ok(fold_unary_op(DslUnaryOp::BitNot, value));
    }
    if stream.consume_char('!') {
        let value = parse_v2_unary_expr(stream, local_scopes)?;
        return Ok(fold_unary_op(DslUnaryOp::BoolNot, value));
    }
    parse_v2_postfix_expr(stream, local_scopes)
}

fn parse_v2_postfix_expr(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslValue, String> {
    let mut value = parse_v2_primary_expr(stream, local_scopes)?;
    loop {
        if stream.consume_ident("as") {
            let class_name = parse_type_name_v2(stream)?;
            value = DslValue::Cast {
                value: Box::new(value),
                class_name,
            };
        } else if stream.consume_char('[') {
            let index = parse_v2_int_binary_expr(stream, local_scopes, 0)?;
            let type_name = if stream.consume_char(':') {
                Some(parse_type_name_v2(stream)?)
            } else {
                None
            };
            if !stream.consume_char(']') {
                return Err(stream.err("expected ']'"));
            }
            value = DslValue::ArrayGet {
                array: Box::new(value),
                index: Box::new(index),
                type_name,
            };
        } else if stream.peek_op("?.") || stream.peek_char('.') {
            value = parse_v2_member_postfix(stream, local_scopes, value)?;
        } else {
            return Ok(value);
        }
    }
}

fn parse_v2_primary_expr(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslValue, String> {
    match stream.current_kind() {
        Some(DslTokenKind::Number(_)) => Ok(DslValue::Int(stream.parse_i16_after_sign(false)?)),
        Some(DslTokenKind::Ident(value)) if value == "true" => {
            stream.advance();
            Ok(DslValue::Bool(true))
        }
        Some(DslTokenKind::Ident(value)) if value == "false" => {
            stream.advance();
            Ok(DslValue::Bool(false))
        }
        Some(DslTokenKind::Ident(value)) if value == "null" => {
            stream.advance();
            Ok(DslValue::Null)
        }
        Some(DslTokenKind::Ident(value)) if value == "orig" => {
            stream.advance();
            if stream.peek_char('(') {
                Ok(DslValue::OrigCall(parse_orig_args_v2(stream, local_scopes)?))
            } else {
                Ok(DslValue::Target(DslTarget::Local("orig".to_string())))
            }
        }
        Some(DslTokenKind::Ident(value)) => {
            let value = value.clone();
            stream.advance();
            Ok(DslValue::Target(
                scoped_target_name_v2(local_scopes, &value).unwrap_or(DslTarget::Local(value)),
            ))
        }
        Some(DslTokenKind::String(value)) => {
            let value = value.clone();
            stream.advance();
            Ok(DslValue::String(value))
        }
        Some(DslTokenKind::Symbol('(')) => {
            stream.advance();
            let value = parse_v2_int_binary_expr(stream, local_scopes, 0)?;
            if !stream.consume_char(')') {
                return Err(stream.err("expected ')'"));
            }
            Ok(value)
        }
        Some(DslTokenKind::Symbol('[')) => parse_v2_array_literal(stream, local_scopes),
        _ => Err(stream.err("not a constant expression")),
    }
}

fn parse_orig_args_v2(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslOrigArgs, String> {
    if !stream.consume_char('(') {
        return Err(stream.err("expected '('"));
    }
    if stream.consume_char(')') {
        return Ok(DslOrigArgs::Original);
    }
    let args = parse_v2_value_arg_list_until_close(stream, local_scopes)?;
    if !stream.consume_char(')') {
        return Err(stream.err("expected ')'"));
    }
    Ok(DslOrigArgs::Values(args))
}

fn parse_v2_array_literal(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslValue, String> {
    if !stream.consume_char('[') {
        return Err(stream.err("expected '['"));
    }
    let mut elements = Vec::new();
    loop {
        if stream.consume_char(']') {
            return Ok(DslValue::ArrayLiteral { elements });
        }
        elements.push(parse_v2_int_binary_expr(stream, local_scopes, 0)?);
        if stream.consume_char(',') {
            if stream.consume_char(']') {
                return Ok(DslValue::ArrayLiteral { elements });
            }
            continue;
        }
        if stream.consume_char(']') {
            return Ok(DslValue::ArrayLiteral { elements });
        }
        return Err(stream.err("array literal expects ',' or ']'"));
    }
}

fn parse_v2_value_arg_list_until_close(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<Vec<DslValue>, String> {
    let mut args = Vec::new();
    loop {
        if stream.peek_char(')') {
            return Ok(args);
        }
        args.push(parse_v2_int_binary_expr(stream, local_scopes, 0)?);
        if !stream.consume_char(',') {
            return Ok(args);
        }
    }
}

fn parse_v2_member_postfix(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
    receiver: DslValue,
) -> Result<DslValue, String> {
    let null_safe = if stream.consume_op("?.") {
        true
    } else if stream.consume_char('.') {
        false
    } else {
        return Err(stream.err("expected member access"));
    };
    let member_name = stream.parse_ident()?;
    if member_name == "length" && !stream.peek_char('(') && !stream.peek_char('.') {
        return Ok(DslValue::ArrayLength(Box::new(receiver)));
    }
    if member_name == "$new" {
        return Err(stream.err("$new is only supported on class names"));
    }

    let mut call_kind = DslCallKind::Virtual;
    if stream.peek_char('.') {
        if !stream.consume_char('.') || !stream.consume_ident("interface") {
            return Err(stream.err("unsupported chained member access in expression v2"));
        }
        call_kind = DslCallKind::Interface;
    }
    if stream.peek_char('.') {
        return Err(stream.err("overload member access is handled by the legacy parser"));
    }
    if !stream.peek_char('(') {
        return build_v2_receiver_field(stream, receiver, member_name, call_kind);
    }
    stream.consume_char('(');
    let args = parse_v2_direct_call_args(stream, local_scopes)?;
    if !stream.consume_char(')') {
        return Err(stream.err("expected ')'"));
    }
    Ok(build_v2_receiver_call(
        receiver,
        null_safe,
        member_name,
        call_kind,
        args,
    ))
}

fn parse_v2_direct_call_args(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<Vec<DslValue>, String> {
    let mut args = Vec::new();
    loop {
        if stream.peek_char(')') {
            return Ok(args);
        }
        if matches!(stream.current_kind(), Some(DslTokenKind::String(_))) {
            return Err(stream.err("string-leading call arguments are handled by the legacy parser"));
        }
        args.push(parse_v2_int_binary_expr(stream, local_scopes, 0)?);
        if !stream.consume_char(',') {
            return Ok(args);
        }
    }
}

fn build_v2_receiver_call(
    receiver: DslValue,
    null_safe: bool,
    method_name: String,
    kind: DslCallKind,
    args: Vec<DslValue>,
) -> DslValue {
    let (target, receiver) = split_simple_target_receiver(receiver);
    DslValue::Call(DslCallStmt {
        kind,
        target,
        receiver: receiver.map(Box::new),
        null_safe,
        class_name: None,
        method_name,
        sig: String::new(),
        args,
    })
}

fn build_v2_receiver_field(
    stream: &DslTokenStream<'_>,
    receiver: DslValue,
    field_name: String,
    kind: DslCallKind,
) -> Result<DslValue, String> {
    if kind == DslCallKind::Interface {
        return Err(stream.err("interface field access is not supported"));
    }
    let (target, receiver) = split_simple_target_receiver(receiver);
    Ok(DslValue::FieldGet {
        stmt: Box::new(DslFieldStmt {
            target,
            receiver: receiver.map(Box::new),
            class_name: None,
            field_name,
            type_name: String::new(),
            value: None,
        }),
        is_static: false,
    })
}

fn split_simple_target_receiver(value: DslValue) -> (Option<DslTarget>, Option<DslValue>) {
    match value {
        DslValue::Target(target) => (Some(target), None),
        value => (None, Some(value)),
    }
}

fn peek_v2_int_binary_op(stream: &DslTokenStream<'_>) -> Option<(DslIntBinOp, u8)> {
    for (token, op, prec) in V2_INT_BINARY_TOKEN_OPS {
        if stream.peek_op(token) {
            return Some((*op, *prec));
        }
    }
    V2_INT_BINARY_CHAR_OPS
        .iter()
        .find_map(|(ch, op, prec)| stream.peek_char(*ch).then_some((*op, *prec)))
}

fn consume_v2_int_binary_op(stream: &mut DslTokenStream<'_>, op: DslIntBinOp) -> Result<(), String> {
    if let Some((token, _, _)) = V2_INT_BINARY_TOKEN_OPS
        .iter()
        .find(|(_, candidate, _)| *candidate == op)
    {
        if stream.consume_op(token) {
            return Ok(());
        }
    }
    if let Some((ch, _, _)) = V2_INT_BINARY_CHAR_OPS.iter().find(|(_, candidate, _)| *candidate == op) {
        if stream.consume_char(*ch) {
            return Ok(());
        }
    }
    Err(stream.err("unsupported integer binary operator"))
}

fn scoped_target_name_v2(local_scopes: &[BTreeMap<String, String>], name: &str) -> Option<DslTarget> {
    match parse_target_name(name) {
        Some(DslTarget::Local(local)) => Some(DslTarget::Local(
            resolve_local_v2(local_scopes, &local).unwrap_or(local),
        )),
        other => other,
    }
}

fn resolve_local_v2(local_scopes: &[BTreeMap<String, String>], source_name: &str) -> Option<String> {
    local_scopes
        .iter()
        .rev()
        .find_map(|scope| scope.get(source_name).cloned())
}

fn parse_type_name_v2(stream: &mut DslTokenStream<'_>) -> Result<String, String> {
    if matches!(stream.current_kind(), Some(DslTokenKind::String(_))) {
        return stream.parse_string();
    }
    let mut name = stream.parse_ident()?;
    loop {
        if stream.consume_char('.') {
            let part = stream.parse_ident()?;
            name.push('.');
            name.push_str(&part);
        } else if stream.consume_char('[') {
            if !stream.consume_char(']') {
                return Err(stream.err("expected ']'"));
            }
            name.push_str("[]");
        } else {
            return Ok(name);
        }
    }
}

fn has_v2_unsupported_trailing_token(stream: &DslTokenStream<'_>) -> bool {
    stream.peek_char('.') || stream.peek_char('(') || stream.peek_op("?.")
}
