use super::{build_method_sig, build_params_sig, java_class_to_descriptor_or_primitive, IfCmpOp};

pub(super) struct DslProgram {
    pub(super) stmts: Vec<DslStmt>,
}

#[derive(Clone)]
pub(super) enum DslStmt {
    Block(Vec<DslStmt>),
    Let {
        name: String,
        type_name: Option<String>,
        value: DslValue,
    },
    Assign {
        name: String,
        value: DslValue,
    },
    LetOrig {
        name: String,
        type_name: Option<String>,
        args: DslOrigArgs,
    },
    New {
        class_name: String,
        ctor_sig: Option<String>,
        args: Vec<DslValue>,
    },
    NewArray {
        array_type_name: String,
        size: DslValue,
    },
    Call(DslCallStmt),
    Cast {
        value: DslValue,
        class_name: String,
    },
    ArrayLength {
        array: DslValue,
    },
    ArrayGet {
        array: DslValue,
        index: DslValue,
        type_name: Option<String>,
    },
    ArrayPut {
        array: DslValue,
        index: DslValue,
        type_name: Option<String>,
        value: DslValue,
    },
    FieldRead {
        stmt: DslFieldStmt,
        is_static: bool,
    },
    FieldWrite {
        stmt: DslFieldStmt,
        is_static: bool,
    },
    IfNull {
        value: DslValue,
        invert: bool,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    IfBool {
        value: DslValue,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    IfCmp {
        op: IfCmpOp,
        left: DslValue,
        right: DslValue,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    IfInstanceOf {
        value: DslValue,
        class_name: String,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    Switch {
        value: DslValue,
        cases: Vec<(i16, Vec<DslStmt>)>,
        default_stmts: Option<Vec<DslStmt>>,
    },
    TryCatch {
        try_stmts: Vec<DslStmt>,
        catch_type: String,
        catch_name: String,
        catch_stmts: Vec<DslStmt>,
    },
    Throw {
        value: DslValue,
    },
    ReturnOrig {
        args: DslOrigArgs,
    },
    ReturnValue {
        value: Option<DslValue>,
    },
}

#[derive(Clone)]
pub(super) enum DslOrigArgs {
    Original,
    Values(Vec<DslValue>),
}

#[derive(Clone)]
pub(super) struct DslCallStmt {
    pub(super) kind: DslCallKind,
    pub(super) target: Option<DslTarget>,
    pub(super) receiver: Option<Box<DslValue>>,
    pub(super) null_safe: bool,
    pub(super) class_name: Option<String>,
    pub(super) method_name: String,
    pub(super) sig: String,
    pub(super) args: Vec<DslValue>,
}

impl DslCallStmt {
    pub(super) fn class_label(&self) -> &str {
        self.class_name.as_deref().unwrap_or("<inferred>")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DslCallKind {
    Virtual,
    Interface,
    Static,
}

enum ParsedCallArgs {
    Direct(Vec<DslValue>),
    LegacyCall {
        class_name: Option<String>,
        sig: String,
        args: Vec<DslValue>,
    },
    Field {
        class_name: Option<String>,
        type_name: String,
    },
}

#[derive(Clone)]
pub(super) struct DslFieldStmt {
    pub(super) target: Option<DslTarget>,
    pub(super) receiver: Option<Box<DslValue>>,
    pub(super) class_name: Option<String>,
    pub(super) field_name: String,
    pub(super) type_name: String,
    pub(super) value: Option<DslValue>,
}

#[derive(Clone)]
pub(super) enum DslValue {
    Target(DslTarget),
    String(String),
    Int(i16),
    Bool(bool),
    Null,
    UnaryOp {
        op: DslUnaryOp,
        value: Box<DslValue>,
    },
    IntBinOp {
        op: DslIntBinOp,
        left: Box<DslValue>,
        right: Box<DslValue>,
    },
    Ternary {
        condition: Box<DslCondition>,
        then_value: Box<DslValue>,
        else_value: Box<DslValue>,
    },
    Call(DslCallStmt),
    NewObject {
        class_name: String,
        ctor_sig: Option<String>,
        args: Vec<DslValue>,
    },
    FieldGet {
        stmt: Box<DslFieldStmt>,
        is_static: bool,
    },
    Cast {
        value: Box<DslValue>,
        class_name: String,
    },
    ArrayLength(Box<DslValue>),
    ArrayGet {
        array: Box<DslValue>,
        index: Box<DslValue>,
        type_name: Option<String>,
    },
}

#[derive(Clone, Copy)]
pub(super) enum DslUnaryOp {
    Neg,
    BitNot,
    BoolNot,
}

#[derive(Clone, Copy)]
pub(super) enum DslIntBinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Ushr,
}

#[derive(Clone)]
pub(super) enum DslCondition {
    Null {
        value: DslValue,
        invert: bool,
    },
    Cmp {
        op: IfCmpOp,
        left: DslValue,
        right: DslValue,
    },
    InstanceOf {
        value: DslValue,
        class_name: String,
    },
    Bool {
        value: DslValue,
    },
    Const(bool),
    And(Box<DslCondition>, Box<DslCondition>),
    Or(Box<DslCondition>, Box<DslCondition>),
    Not(Box<DslCondition>),
}

impl DslCondition {
    fn into_if_stmt(self, then_stmts: Vec<DslStmt>, else_stmts: Vec<DslStmt>) -> DslStmt {
        match self {
            DslCondition::Const(true) => DslStmt::Block(then_stmts),
            DslCondition::Const(false) => DslStmt::Block(else_stmts),
            DslCondition::Null { value, invert } => DslStmt::IfNull {
                value,
                invert,
                then_stmts,
                else_stmts,
            },
            DslCondition::Bool { value } => DslStmt::IfBool {
                value,
                then_stmts,
                else_stmts,
            },
            DslCondition::Cmp { op, left, right } => DslStmt::IfCmp {
                op,
                left,
                right,
                then_stmts,
                else_stmts,
            },
            DslCondition::InstanceOf { value, class_name } => DslStmt::IfInstanceOf {
                value,
                class_name,
                then_stmts,
                else_stmts,
            },
            DslCondition::And(left, right) => {
                let inner = right.into_if_stmt(then_stmts, else_stmts.clone());
                left.into_if_stmt(vec![inner], else_stmts)
            }
            DslCondition::Or(left, right) => {
                let inner = right.into_if_stmt(then_stmts.clone(), else_stmts);
                left.into_if_stmt(then_stmts, vec![inner])
            }
            DslCondition::Not(condition) => condition.into_if_stmt(else_stmts, then_stmts),
        }
    }
}

fn condition_and(left: DslCondition, right: DslCondition) -> DslCondition {
    match (left, right) {
        (DslCondition::Const(false), _) | (_, DslCondition::Const(false)) => DslCondition::Const(false),
        (DslCondition::Const(true), right) => right,
        (left, DslCondition::Const(true)) => left,
        (left, right) => DslCondition::And(Box::new(left), Box::new(right)),
    }
}

fn condition_or(left: DslCondition, right: DslCondition) -> DslCondition {
    match (left, right) {
        (DslCondition::Const(true), _) | (_, DslCondition::Const(true)) => DslCondition::Const(true),
        (DslCondition::Const(false), right) => right,
        (left, DslCondition::Const(false)) => left,
        (left, right) => DslCondition::Or(Box::new(left), Box::new(right)),
    }
}

fn condition_not(condition: DslCondition) -> DslCondition {
    match condition {
        DslCondition::Const(value) => DslCondition::Const(!value),
        DslCondition::Not(inner) => *inner,
        other => DslCondition::Not(Box::new(other)),
    }
}

fn fold_ternary(condition: DslCondition, then_value: DslValue, else_value: DslValue) -> DslValue {
    match condition {
        DslCondition::Const(true) => then_value,
        DslCondition::Const(false) => else_value,
        condition => DslValue::Ternary {
            condition: Box::new(condition),
            then_value: Box::new(then_value),
            else_value: Box::new(else_value),
        },
    }
}

impl DslValue {
    fn into_bool_condition(self) -> DslCondition {
        match self {
            DslValue::Bool(value) => DslCondition::Const(value),
            value => DslCondition::Bool { value },
        }
    }

    fn into_statement(self) -> Option<DslStmt> {
        match self {
            DslValue::Call(stmt) => Some(DslStmt::Call(stmt)),
            DslValue::NewObject {
                class_name,
                ctor_sig,
                args,
            } => Some(DslStmt::New {
                class_name,
                ctor_sig,
                args,
            }),
            DslValue::FieldGet { stmt, is_static } => Some(DslStmt::FieldRead { stmt: *stmt, is_static }),
            DslValue::Cast { value, class_name } => Some(DslStmt::Cast {
                value: *value,
                class_name,
            }),
            DslValue::ArrayLength(array) => Some(DslStmt::ArrayLength { array: *array }),
            DslValue::ArrayGet {
                array,
                index,
                type_name,
            } => Some(DslStmt::ArrayGet {
                array: *array,
                index: *index,
                type_name,
            }),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub(super) enum DslTarget {
    This,
    Arg(usize),
    Last,
    Result,
    Local(String),
}

pub(super) fn parse_managed_dsl(dsl: &str) -> Result<DslProgram, String> {
    let mut parser = DslParser::new(dsl)?;
    let stmts = parser.parse_statements(false)?;
    parser.skip_ws();
    parser.expect_eof()?;
    Ok(DslProgram { stmts })
}

impl<'a> DslParser<'a> {
    fn parse_statements(&mut self, stop_on_brace: bool) -> Result<Vec<DslStmt>, String> {
        let mut stmts = Vec::new();
        loop {
            self.skip_ws();
            if self.is_eof() {
                if stop_on_brace {
                    return Err(self.err("expected '}'"));
                }
                break;
            }
            if stop_on_brace && self.peek() == Some('}') {
                self.expect_char('}')?;
                break;
            }
            let stmt = self.parse_statement()?;
            stmts.push(stmt);
        }
        Ok(stmts)
    }

    fn parse_block(&mut self) -> Result<Vec<DslStmt>, String> {
        self.skip_ws();
        self.expect_char('{')?;
        self.parse_statements(true)
    }

    fn parse_statement(&mut self) -> Result<DslStmt, String> {
        self.skip_ws();
        if self.peek_ident("return") {
            self.expect_ident("return")?;
            self.skip_ws();
            if self.peek_ident("orig") {
                self.expect_ident("orig")?;
                let args = self.parse_orig_args()?;
                self.skip_ws();
                self.expect_char(';')?;
                return Ok(DslStmt::ReturnOrig { args });
            }
            let value = if self.peek() == Some(';') {
                None
            } else {
                Some(self.parse_value_arg()?)
            };
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(DslStmt::ReturnValue { value });
        }
        if self.peek_ident("throw") {
            self.expect_ident("throw")?;
            let value = self.parse_value_arg()?;
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(DslStmt::Throw { value });
        }
        if self.peek_ident("if") {
            return self.parse_js_if_statement();
        }
        if self.peek_ident("switch") {
            return self.parse_js_switch_statement();
        }
        if self.peek_ident("try") {
            return self.parse_js_try_catch_statement();
        }

        let name = self.parse_ident()?;
        self.skip_ws();
        if name == "let" && self.peek() != Some('(') {
            return self.parse_js_let_statement();
        }
        if name == "new" && self.peek() != Some('(') {
            let stmt = self.parse_js_new_statement()?;
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(stmt);
        }
        if self.peek() == Some('=') {
            self.expect_char('=')?;
            let value = self.parse_value_arg()?;
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(DslStmt::Assign { name, value });
        }
        if self.peek() == Some('.') || self.peek() == Some('[') || self.peek_ident("as") {
            let value = self.parse_value_from_ident(name)?;
            self.skip_ws();
            if self.peek() == Some('=') {
                self.expect_char('=')?;
                let rhs = self.parse_value_arg()?;
                self.skip_ws();
                self.expect_char(';')?;
                return match value {
                    DslValue::FieldGet { stmt, is_static } => {
                        let mut stmt = *stmt;
                        stmt.value = Some(rhs);
                        Ok(DslStmt::FieldWrite { stmt, is_static })
                    }
                    DslValue::ArrayGet {
                        array,
                        index,
                        type_name,
                    } => Ok(DslStmt::ArrayPut {
                        array: *array,
                        index: *index,
                        type_name,
                        value: rhs,
                    }),
                    _ => Err(self.err("only fields and array elements can be assigned")),
                };
            }
            self.expect_char(';')?;
            return value
                .into_statement()
                .ok_or_else(|| self.err("only method calls and field reads can be used as expression statements"));
        }
        Err(self.err(&format!("unknown managed DSL statement '{}'", name)))
    }

    fn parse_js_let_statement(&mut self) -> Result<DslStmt, String> {
        self.skip_ws();
        let local_name = self.parse_ident()?;
        self.skip_ws();
        let type_name = if self.peek() == Some(':') {
            self.expect_char(':')?;
            Some(self.parse_type_name()?)
        } else {
            None
        };
        self.skip_ws();
        self.expect_char('=')?;
        self.skip_ws();
        if self.peek_ident("orig") {
            self.expect_ident("orig")?;
            let args = self.parse_orig_args()?;
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(DslStmt::LetOrig {
                name: local_name,
                type_name,
                args,
            });
        }
        let value = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(';')?;
        Ok(DslStmt::Let {
            name: local_name,
            type_name,
            value,
        })
    }

    fn parse_orig_args(&mut self) -> Result<DslOrigArgs, String> {
        self.skip_ws();
        self.expect_char('(')?;
        self.skip_ws();
        if self.peek() == Some(')') {
            self.expect_char(')')?;
            return Ok(DslOrigArgs::Original);
        }
        let args = self.parse_value_arg_list_until_close()?;
        self.skip_ws();
        self.expect_char(')')?;
        Ok(DslOrigArgs::Values(args))
    }

    fn parse_js_new_statement(&mut self) -> Result<DslStmt, String> {
        self.skip_ws();
        let class_name = self.parse_type_name()?;
        self.skip_ws();
        self.expect_char('(')?;
        self.skip_ws();
        if class_name.ends_with("[]") {
            let size = self.parse_value_arg()?;
            self.skip_ws();
            self.expect_char(')')?;
            return Ok(DslStmt::NewArray {
                array_type_name: class_name,
                size,
            });
        }
        let (ctor_sig, args) = self.parse_new_constructor_args()?;
        self.expect_char(')')?;
        Ok(DslStmt::New {
            class_name,
            ctor_sig,
            args,
        })
    }

    fn parse_new_constructor_args(&mut self) -> Result<(Option<String>, Vec<DslValue>), String> {
        enum NewArgToken {
            String(String),
            Value(DslValue),
        }

        fn token_to_value(token: NewArgToken) -> DslValue {
            match token {
                NewArgToken::String(value) => DslValue::String(value),
                NewArgToken::Value(value) => value,
            }
        }

        self.skip_ws();
        if self.peek() == Some(')') {
            return Ok((None, Vec::new()));
        }

        let mut tokens = Vec::new();
        loop {
            self.skip_ws();
            let token = if self.peek_string() {
                NewArgToken::String(self.parse_string_arg()?)
            } else {
                NewArgToken::Value(self.parse_value_arg()?)
            };
            tokens.push(token);
            self.skip_ws();
            if self.peek() != Some(',') {
                break;
            }
            self.expect_char(',')?;
        }

        let Some(NewArgToken::String(first)) = tokens.first() else {
            return Err(self.err("constructor arguments must start with a signature or parameter type list"));
        };
        if first.starts_with('(') {
            let sig = first.clone();
            let args = tokens.into_iter().skip(1).map(token_to_value).collect::<Vec<_>>();
            return Ok((Some(sig), args));
        }

        let mut resolved_type_count = None;
        let mut resolved_sig = None;
        if tokens.len() % 2 == 0 {
            let type_count = tokens.len() / 2;
            let mut params = Vec::with_capacity(type_count);
            let mut all_types = true;
            for token in &tokens[..type_count] {
                let NewArgToken::String(type_name) = token else {
                    all_types = false;
                    break;
                };
                match java_class_to_descriptor_or_primitive(type_name) {
                    Ok(desc) => params.push(desc),
                    Err(_) => {
                        all_types = false;
                        break;
                    }
                }
            }
            if all_types {
                resolved_type_count = Some(type_count);
                resolved_sig = Some(build_method_sig(&params, "V"));
            }
        }

        let Some(type_count) = resolved_type_count else {
            return Err(self.err(
                "constructor expects either a full JNI signature or parameter type list followed by matching args",
            ));
        };
        let args = tokens
            .into_iter()
            .skip(type_count)
            .map(token_to_value)
            .collect::<Vec<_>>();
        Ok((resolved_sig, args))
    }

    fn parse_js_if_statement(&mut self) -> Result<DslStmt, String> {
        self.expect_ident("if")?;
        self.skip_ws();
        self.expect_char('(')?;
        let condition = self.parse_js_if_condition()?;
        self.expect_char(')')?;
        let then_stmts = self.parse_block()?;
        self.skip_ws();
        let else_stmts = if self.peek_ident("else") {
            self.expect_ident("else")?;
            self.skip_ws();
            if self.peek_ident("if") {
                vec![self.parse_js_if_statement()?]
            } else {
                self.parse_block()?
            }
        } else {
            Vec::new()
        };
        Ok(condition.into_if_stmt(then_stmts, else_stmts))
    }

    fn parse_js_switch_statement(&mut self) -> Result<DslStmt, String> {
        self.expect_ident("switch")?;
        self.skip_ws();
        self.expect_char('(')?;
        let value = self.parse_value_arg()?;
        self.expect_char(')')?;
        self.skip_ws();
        self.expect_char('{')?;

        let mut cases = Vec::<(i16, Vec<DslStmt>)>::new();
        let mut default_stmts = None::<Vec<DslStmt>>;
        loop {
            self.skip_ws();
            if self.peek() == Some('}') {
                self.expect_char('}')?;
                break;
            }
            if self.peek_ident("case") {
                self.expect_ident("case")?;
                let literal = self.parse_i16()?;
                self.expect_char(':')?;
                let stmts = self.parse_block()?;
                cases.push((literal, stmts));
            } else if self.peek_ident("default") {
                if default_stmts.is_some() {
                    return Err(self.err("switch supports only one default block"));
                }
                self.expect_ident("default")?;
                self.skip_ws();
                self.expect_char(':')?;
                default_stmts = Some(self.parse_block()?);
            } else {
                return Err(self.err("expected switch case/default block"));
            }
        }
        if cases.is_empty() {
            return Err(self.err("switch requires at least one case"));
        }

        Ok(DslStmt::Switch {
            value,
            cases,
            default_stmts,
        })
    }

    fn parse_js_try_catch_statement(&mut self) -> Result<DslStmt, String> {
        self.expect_ident("try")?;
        let try_stmts = self.parse_block()?;
        self.skip_ws();
        self.expect_ident("catch")?;
        self.skip_ws();
        self.expect_char('(')?;
        let catch_type = self.parse_type_name()?;
        self.skip_ws();
        let catch_name = self.parse_ident()?;
        self.skip_ws();
        self.expect_char(')')?;
        let catch_stmts = self.parse_block()?;
        Ok(DslStmt::TryCatch {
            try_stmts,
            catch_type,
            catch_name,
            catch_stmts,
        })
    }
}

#[derive(Clone, Debug)]
enum DslTokenKind {
    Ident(String),
    String(String),
    Number(String),
    Symbol(char),
    Op(&'static str),
}

#[derive(Clone, Debug)]
struct DslToken {
    kind: DslTokenKind,
    byte: usize,
}

fn dsl_lex(input: &str) -> Result<Vec<DslToken>, String> {
    let mut tokens = Vec::new();
    let mut pos = 0usize;
    while pos < input.len() {
        let ch = input[pos..].chars().next().unwrap();
        if ch.is_whitespace() {
            pos += ch.len_utf8();
            continue;
        }
        let byte = pos;
        if is_ident_start(ch) {
            pos += ch.len_utf8();
            while pos < input.len() {
                let next = input[pos..].chars().next().unwrap();
                if is_ident_continue(next) {
                    pos += next.len_utf8();
                } else {
                    break;
                }
            }
            tokens.push(DslToken {
                kind: DslTokenKind::Ident(input[byte..pos].to_string()),
                byte,
            });
            continue;
        }
        if ch.is_ascii_digit() {
            pos += 1;
            while pos < input.len() {
                let next = input.as_bytes()[pos] as char;
                if next.is_ascii_digit() {
                    pos += 1;
                } else {
                    break;
                }
            }
            tokens.push(DslToken {
                kind: DslTokenKind::Number(input[byte..pos].to_string()),
                byte,
            });
            continue;
        }
        if ch == '"' {
            pos += 1;
            let mut out = String::new();
            loop {
                if pos >= input.len() {
                    return Err(format!(
                        "managed dex DSL parse error at byte {}: unterminated string",
                        byte
                    ));
                }
                let current = input[pos..].chars().next().unwrap();
                pos += current.len_utf8();
                match current {
                    '"' => break,
                    '\\' => {
                        if pos >= input.len() {
                            return Err(format!(
                                "managed dex DSL parse error at byte {}: unterminated string escape",
                                pos
                            ));
                        }
                        let escaped = input[pos..].chars().next().unwrap();
                        pos += escaped.len_utf8();
                        match escaped {
                            '"' => out.push('"'),
                            '\\' => out.push('\\'),
                            'n' => out.push('\n'),
                            'r' => out.push('\r'),
                            't' => out.push('\t'),
                            other => {
                                return Err(format!(
                                    "managed dex DSL parse error at byte {}: unsupported string escape \\{}",
                                    pos - other.len_utf8(),
                                    other
                                ));
                            }
                        }
                    }
                    other => out.push(other),
                }
            }
            tokens.push(DslToken {
                kind: DslTokenKind::String(out),
                byte,
            });
            continue;
        }
        let rest = &input[pos..];
        let op = if rest.starts_with(">>>") {
            Some(">>>")
        } else if rest.starts_with("<<") {
            Some("<<")
        } else if rest.starts_with(">>") {
            Some(">>")
        } else if rest.starts_with("==") {
            Some("==")
        } else if rest.starts_with("!=") {
            Some("!=")
        } else if rest.starts_with("<=") {
            Some("<=")
        } else if rest.starts_with(">=") {
            Some(">=")
        } else if rest.starts_with("&&") {
            Some("&&")
        } else if rest.starts_with("||") {
            Some("||")
        } else if rest.starts_with("?.") {
            Some("?.")
        } else {
            None
        };
        if let Some(op) = op {
            pos += op.len();
            tokens.push(DslToken {
                kind: DslTokenKind::Op(op),
                byte,
            });
            continue;
        }
        if "{}()[];:,.?+-=<>!*/%&|^~".contains(ch) {
            pos += ch.len_utf8();
            tokens.push(DslToken {
                kind: DslTokenKind::Symbol(ch),
                byte,
            });
            continue;
        }
        return Err(format!(
            "managed dex DSL parse error at byte {}: unexpected character '{}'",
            byte, ch
        ));
    }
    Ok(tokens)
}

struct DslParser<'a> {
    input: &'a str,
    tokens: Vec<DslToken>,
    pos: usize,
}

impl<'a> DslParser<'a> {
    fn new(input: &'a str) -> Result<Self, String> {
        Ok(Self {
            input,
            tokens: dsl_lex(input)?,
            pos: 0,
        })
    }

    fn skip_ws(&mut self) {}

    fn expect_ident(&mut self, expected: &str) -> Result<(), String> {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::Ident(value)) if value == expected => {
                self.pos += 1;
                Ok(())
            }
            _ => Err(self.err(&format!("expected identifier {}", expected))),
        }
    }

    fn peek_ident(&self, expected: &str) -> bool {
        matches!(self.tokens.get(self.pos).map(|token| &token.kind), Some(DslTokenKind::Ident(value)) if value == expected)
    }

    fn parse_ident(&mut self) -> Result<String, String> {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::Ident(value)) => {
                self.pos += 1;
                Ok(value.clone())
            }
            _ => Err(self.err("expected identifier")),
        }
    }

    fn expect_char(&mut self, expected: char) -> Result<(), String> {
        match self.peek() {
            Some(ch) if ch == expected => {
                self.pos += 1;
                Ok(())
            }
            _ => Err(self.err(&format!("expected '{}'", expected))),
        }
    }

    fn parse_string_arg(&mut self) -> Result<String, String> {
        self.skip_ws();
        let value = self.parse_string()?;
        self.skip_ws();
        Ok(value)
    }

    fn parse_string(&mut self) -> Result<String, String> {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::String(value)) => {
                self.pos += 1;
                Ok(value.clone())
            }
            _ => Err(self.err("expected string")),
        }
    }

    fn parse_type_name(&mut self) -> Result<String, String> {
        self.skip_ws();
        if self.peek_string() {
            return self.parse_string_arg();
        }
        let mut name = self.parse_ident()?;
        loop {
            self.skip_ws();
            match self.peek() {
                Some('.') => {
                    self.expect_char('.')?;
                    let part = self.parse_ident()?;
                    name.push('.');
                    name.push_str(&part);
                }
                Some('[') => {
                    self.expect_char('[')?;
                    self.expect_char(']')?;
                    name.push_str("[]");
                }
                _ => break,
            }
        }
        self.skip_ws();
        Ok(name)
    }

    fn parse_i16(&mut self) -> Result<i16, String> {
        self.skip_ws();
        let negative = if self.peek() == Some('-') {
            self.pos += 1;
            true
        } else {
            false
        };
        let value_text = match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::Number(value)) => {
                self.pos += 1;
                value.clone()
            }
            _ => return Err(self.err("expected integer")),
        };
        let value: i32 = value_text.parse().map_err(|_| self.err("invalid integer"))?;
        let signed = if negative { -value } else { value };
        if signed < i16::MIN as i32 || signed > i16::MAX as i32 {
            return Err(self.err("integer must fit int16"));
        }
        self.skip_ws();
        Ok(signed as i16)
    }

    fn parse_value_arg(&mut self) -> Result<DslValue, String> {
        self.parse_ternary_expr()
    }

    fn parse_non_ternary_value_arg(&mut self) -> Result<DslValue, String> {
        self.parse_int_binary_expr(0)
    }

    fn parse_ternary_expr(&mut self) -> Result<DslValue, String> {
        let checkpoint = self.pos;
        if let Ok(condition) = self.parse_js_condition() {
            self.skip_ws();
            if self.peek() == Some('?') {
                self.expect_char('?')?;
                let then_value = self.parse_value_arg()?;
                self.expect_char(':')?;
                let else_value = self.parse_value_arg()?;
                return Ok(fold_ternary(condition, then_value, else_value));
            }
        }
        self.pos = checkpoint;
        self.parse_int_binary_expr(0)
    }

    fn parse_int_binary_expr(&mut self, min_prec: u8) -> Result<DslValue, String> {
        let mut left = self.parse_value_unary()?;
        loop {
            self.skip_ws();
            let Some((op, prec)) = self.peek_int_binary_op() else {
                break;
            };
            if prec < min_prec {
                break;
            }
            self.consume_int_binary_op(op)?;
            let right = self.parse_int_binary_expr(prec + 1)?;
            left = fold_int_binop(op, left, right);
        }
        Ok(left)
    }

    fn parse_value_unary(&mut self) -> Result<DslValue, String> {
        self.skip_ws();
        if self.peek() == Some('-') {
            self.expect_char('-')?;
            if self.peek_number() {
                self.pos = self.pos.saturating_sub(1);
                return Ok(DslValue::Int(self.parse_i16()?));
            }
            let value = self.parse_value_unary()?;
            return Ok(fold_unary_op(DslUnaryOp::Neg, value));
        }
        if self.peek() == Some('~') {
            self.expect_char('~')?;
            let value = self.parse_value_unary()?;
            return Ok(fold_unary_op(DslUnaryOp::BitNot, value));
        }
        if self.peek() == Some('!') {
            self.expect_char('!')?;
            let value = self.parse_value_unary()?;
            return Ok(fold_unary_op(DslUnaryOp::BoolNot, value));
        }
        self.parse_value_primary()
    }

    fn parse_value_primary(&mut self) -> Result<DslValue, String> {
        self.skip_ws();
        let value = if self.peek_string() {
            DslValue::String(self.parse_string()?)
        } else if self.peek_number() {
            DslValue::Int(self.parse_i16()?)
        } else if self.peek() == Some('(') {
            self.expect_char('(')?;
            let value = self.parse_value_arg()?;
            self.expect_char(')')?;
            value
        } else {
            let ident = self.parse_ident()?;
            if ident == "null" {
                DslValue::Null
            } else if ident == "true" {
                DslValue::Bool(true)
            } else if ident == "false" {
                DslValue::Bool(false)
            } else {
                self.parse_value_from_ident(ident)?
            }
        };
        self.skip_ws();
        self.parse_value_postfix(value)
    }

    fn peek_int_binary_op(&mut self) -> Option<(DslIntBinOp, u8)> {
        self.skip_ws();
        if self.peek_op(">>>") {
            return Some((DslIntBinOp::Ushr, 5));
        }
        if self.peek_op("<<") {
            return Some((DslIntBinOp::Shl, 5));
        }
        if self.peek_op(">>") {
            return Some((DslIntBinOp::Shr, 5));
        }
        match self.peek()? {
            '|' => Some((DslIntBinOp::Or, 1)),
            '^' => Some((DslIntBinOp::Xor, 2)),
            '&' => Some((DslIntBinOp::And, 3)),
            '+' => Some((DslIntBinOp::Add, 6)),
            '-' => Some((DslIntBinOp::Sub, 6)),
            '*' => Some((DslIntBinOp::Mul, 7)),
            '/' => Some((DslIntBinOp::Div, 7)),
            '%' => Some((DslIntBinOp::Rem, 7)),
            _ => None,
        }
    }

    fn consume_int_binary_op(&mut self, op: DslIntBinOp) -> Result<(), String> {
        match op {
            DslIntBinOp::Ushr => self.expect_op(">>>"),
            DslIntBinOp::Shl => self.expect_op("<<"),
            DslIntBinOp::Shr => self.expect_op(">>"),
            DslIntBinOp::Or => self.expect_char('|'),
            DslIntBinOp::Xor => self.expect_char('^'),
            DslIntBinOp::And => self.expect_char('&'),
            DslIntBinOp::Add => self.expect_char('+'),
            DslIntBinOp::Sub => self.expect_char('-'),
            DslIntBinOp::Mul => self.expect_char('*'),
            DslIntBinOp::Div => self.expect_char('/'),
            DslIntBinOp::Rem => self.expect_char('%'),
        }
    }

    fn parse_value_from_ident(&mut self, ident: String) -> Result<DslValue, String> {
        self.skip_ws();
        let value = if self.peek() == Some('.') {
            self.parse_js_member_value(ident)?
        } else {
            let target = parse_target_name(&ident);
            let target = target.unwrap_or_else(|| DslTarget::Local(ident));
            DslValue::Target(target)
        };
        self.parse_value_postfix(value)
    }

    fn parse_value_postfix(&mut self, mut value: DslValue) -> Result<DslValue, String> {
        loop {
            self.skip_ws();
            if self.peek_ident("as") {
                self.expect_ident("as")?;
                let class_name = self.parse_type_name()?;
                value = DslValue::Cast {
                    value: Box::new(value),
                    class_name,
                };
            } else if self.peek() == Some('[') {
                self.expect_char('[')?;
                let index = self.parse_value_arg()?;
                let type_name = if self.peek() == Some(':') {
                    self.expect_char(':')?;
                    Some(self.parse_type_name()?)
                } else {
                    None
                };
                self.expect_char(']')?;
                value = DslValue::ArrayGet {
                    array: Box::new(value),
                    index: Box::new(index),
                    type_name,
                };
            } else if self.peek_op("?.") {
                value = self.parse_postfix_member_value(value, true)?;
            } else if self.peek() == Some('.') {
                value = self.parse_postfix_member_value(value, false)?;
            } else {
                return Ok(value);
            }
        }
    }

    fn parse_postfix_member_value(&mut self, receiver: DslValue, null_safe: bool) -> Result<DslValue, String> {
        if null_safe {
            self.expect_op("?.")?;
        } else {
            self.expect_char('.')?;
        }
        let member_name = self.parse_ident()?;
        self.skip_ws();

        if member_name == "length" && self.peek() != Some('(') && self.peek() != Some('.') {
            return Ok(DslValue::ArrayLength(Box::new(receiver)));
        }
        if member_name == "$new" {
            return Err(self.err("$new is only supported on class names"));
        }

        let call_kind = if self.peek() == Some('.') {
            let checkpoint = self.pos;
            self.expect_char('.')?;
            if self.peek_ident("interface") {
                self.expect_ident("interface")?;
                self.skip_ws();
                DslCallKind::Interface
            } else {
                self.pos = checkpoint;
                DslCallKind::Virtual
            }
        } else {
            DslCallKind::Virtual
        };

        if self.peek() == Some('.') {
            self.expect_char('.')?;
            self.expect_ident("overload")?;
            return self.parse_postfix_overload_call(receiver, member_name, call_kind, null_safe);
        }

        if self.peek() != Some('(') {
            if call_kind == DslCallKind::Interface {
                return Err(self.err("interface field access is not supported"));
            }
            return Ok(DslValue::FieldGet {
                stmt: Box::new(DslFieldStmt {
                    target: None,
                    receiver: Some(Box::new(receiver)),
                    class_name: None,
                    field_name: member_name,
                    type_name: String::new(),
                    value: None,
                }),
                is_static: false,
            });
        }

        self.expect_char('(')?;
        match self.parse_member_call_args(true, false)? {
            ParsedCallArgs::Direct(args) => Ok(DslValue::Call(DslCallStmt {
                kind: call_kind,
                target: None,
                receiver: Some(Box::new(receiver)),
                null_safe,
                class_name: None,
                method_name: member_name,
                sig: String::new(),
                args,
            })),
            ParsedCallArgs::LegacyCall { class_name, sig, args } => Ok(DslValue::Call(DslCallStmt {
                kind: call_kind,
                target: None,
                receiver: Some(Box::new(receiver)),
                null_safe,
                class_name,
                method_name: member_name,
                sig,
                args,
            })),
            ParsedCallArgs::Field { type_name, .. } => {
                if call_kind == DslCallKind::Interface {
                    return Err(self.err("interface field access is not supported"));
                }
                Ok(DslValue::FieldGet {
                    stmt: Box::new(DslFieldStmt {
                        target: None,
                        receiver: Some(Box::new(receiver)),
                        class_name: None,
                        field_name: member_name,
                        type_name,
                        value: None,
                    }),
                    is_static: false,
                })
            }
        }
    }

    fn parse_postfix_overload_call(
        &mut self,
        receiver: DslValue,
        method_name: String,
        call_kind: DslCallKind,
        null_safe: bool,
    ) -> Result<DslValue, String> {
        self.expect_char('(')?;
        self.skip_ws();
        let mut overload_args = Vec::new();
        if self.peek() != Some(')') {
            loop {
                overload_args.push(self.parse_string_arg()?);
                if self.peek() != Some(',') {
                    break;
                }
                self.expect_char(',')?;
                self.skip_ws();
            }
        }
        self.expect_char(')')?;
        self.skip_ws();
        self.expect_char('(')?;
        let args = self.parse_value_arg_list_until_close()?;
        self.expect_char(')')?;

        let (class_name, params) = if call_kind == DslCallKind::Interface {
            let Some(class_name) = overload_args.first() else {
                return Err(self.err("interface overload expects overload(\"InterfaceClass\", ...)"));
            };
            if class_name.starts_with('(') {
                return Err(self.err("interface overload expects overload(\"InterfaceClass\", ...)"));
            }
            let params = if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
                overload_args[1].clone()
            } else {
                let param_types = overload_args[1..]
                    .iter()
                    .map(|arg| java_class_to_descriptor_or_primitive(arg))
                    .collect::<Result<Vec<_>, _>>()?;
                build_params_sig(&param_types)
            };
            (Some(class_name.clone()), params)
        } else if overload_args.first().map(|arg| arg.starts_with('(')).unwrap_or(false) {
            if overload_args.len() != 1 {
                return Err(self.err("full-signature overload expects overload(\"sig\")"));
            }
            (None, overload_args[0].clone())
        } else if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
            (Some(overload_args[0].clone()), overload_args[1].clone())
        } else {
            let param_types = overload_args
                .iter()
                .map(|arg| java_class_to_descriptor_or_primitive(arg))
                .collect::<Result<Vec<_>, _>>()?;
            (None, build_params_sig(&param_types))
        };

        Ok(DslValue::Call(DslCallStmt {
            kind: call_kind,
            target: None,
            receiver: Some(Box::new(receiver)),
            null_safe,
            class_name,
            method_name,
            sig: params,
            args,
        }))
    }

    fn parse_member_call_args(
        &mut self,
        allow_field: bool,
        allow_explicit_class: bool,
    ) -> Result<ParsedCallArgs, String> {
        self.skip_ws();
        if self.peek() == Some(')') {
            self.expect_char(')')?;
            return Ok(ParsedCallArgs::Direct(Vec::new()));
        }

        if self.peek_string() {
            let first = self.parse_string_arg()?;
            self.skip_ws();
            if first.starts_with('(') {
                let args = self.parse_optional_value_args()?;
                self.expect_char(')')?;
                return Ok(ParsedCallArgs::LegacyCall {
                    class_name: None,
                    sig: first,
                    args,
                });
            }
            if allow_explicit_class && self.peek() == Some(',') && looks_like_type_name(&first) {
                let checkpoint = self.pos;
                self.expect_char(',')?;
                self.skip_ws();
                if self.peek_string() {
                    let second = self.parse_string_arg()?;
                    if second.starts_with('(') {
                        let args = self.parse_optional_value_args()?;
                        self.expect_char(')')?;
                        return Ok(ParsedCallArgs::LegacyCall {
                            class_name: Some(first),
                            sig: second,
                            args,
                        });
                    }
                }
                self.pos = checkpoint;
            }
            if allow_field && self.peek() == Some(')') && looks_like_type_name(&first) {
                self.expect_char(')')?;
                return Ok(ParsedCallArgs::Field {
                    class_name: None,
                    type_name: first,
                });
            }

            let mut args = vec![DslValue::String(first)];
            while self.peek() == Some(',') {
                self.expect_char(',')?;
                args.push(self.parse_value_arg()?);
                self.skip_ws();
            }
            self.expect_char(')')?;
            return Ok(ParsedCallArgs::Direct(args));
        }

        let args = self.parse_value_arg_list_until_close()?;
        self.expect_char(')')?;
        Ok(ParsedCallArgs::Direct(args))
    }

    fn parse_js_member_value(&mut self, first: String) -> Result<DslValue, String> {
        let mut parts = vec![first];
        while self.peek() == Some('.') {
            self.expect_char('.')?;
            parts.push(self.parse_ident()?);
            self.skip_ws();
            if parts.last().map(|part| part.as_str()) == Some("overload") {
                return self.parse_js_overload_member_value(parts);
            }
        }
        if parts.len() < 2 {
            return Err(self.err("expected member access"));
        }
        if parts.last().map(|part| part.as_str()) == Some("$new") {
            return self.parse_js_new_member_value(parts);
        }
        if parts.len() == 2 && parts[1] == "length" && self.peek() != Some('(') {
            let target = parse_target_name(&parts[0]).unwrap_or_else(|| DslTarget::Local(parts[0].clone()));
            return Ok(DslValue::ArrayLength(Box::new(DslValue::Target(target))));
        }
        if self.peek() != Some('(') {
            if parts.len() == 2 && !looks_like_static_class_name(&parts[0]) {
                let target = parse_target_name(&parts[0]).unwrap_or_else(|| DslTarget::Local(parts[0].clone()));
                return Ok(DslValue::FieldGet {
                    stmt: Box::new(DslFieldStmt {
                        target: Some(target),
                        receiver: None,
                        class_name: None,
                        field_name: parts[1].clone(),
                        type_name: String::new(),
                        value: None,
                    }),
                    is_static: false,
                });
            }
            return Err(
                self.err("direct field access currently supports only instance fields on this/arg/local values")
            );
        }
        self.expect_char('(')?;

        if parts.len() == 2 && parse_target_name(&parts[0]).is_some() {
            let target = parse_target_name(&parts[0]).unwrap();
            match self.parse_member_call_args(true, matches!(target, DslTarget::Last | DslTarget::Result))? {
                ParsedCallArgs::Direct(args) => Ok(DslValue::Call(DslCallStmt {
                    kind: DslCallKind::Virtual,
                    target: Some(target),
                    receiver: None,
                    null_safe: false,
                    class_name: None,
                    method_name: parts[1].clone(),
                    sig: String::new(),
                    args,
                })),
                ParsedCallArgs::LegacyCall { class_name, sig, args } => Ok(DslValue::Call(DslCallStmt {
                    kind: DslCallKind::Virtual,
                    target: Some(target),
                    receiver: None,
                    null_safe: false,
                    class_name,
                    method_name: parts[1].clone(),
                    sig,
                    args,
                })),
                ParsedCallArgs::Field { class_name, type_name } => Ok(DslValue::FieldGet {
                    stmt: Box::new(DslFieldStmt {
                        target: Some(target),
                        receiver: None,
                        class_name,
                        field_name: parts[1].clone(),
                        type_name,
                        value: None,
                    }),
                    is_static: false,
                }),
            }
        } else {
            let member_name = parts.pop().unwrap();
            let class_name = parts.join(".");
            match self.parse_member_call_args(true, false)? {
                ParsedCallArgs::Direct(args) => Ok(DslValue::Call(DslCallStmt {
                    kind: DslCallKind::Static,
                    target: None,
                    receiver: None,
                    null_safe: false,
                    class_name: Some(class_name),
                    method_name: member_name,
                    sig: String::new(),
                    args,
                })),
                ParsedCallArgs::LegacyCall { sig, args, .. } => Ok(DslValue::Call(DslCallStmt {
                    kind: DslCallKind::Static,
                    target: None,
                    receiver: None,
                    null_safe: false,
                    class_name: Some(class_name),
                    method_name: member_name,
                    sig,
                    args,
                })),
                ParsedCallArgs::Field { type_name, .. } => Ok(DslValue::FieldGet {
                    stmt: Box::new(DslFieldStmt {
                        target: None,
                        receiver: None,
                        class_name: Some(class_name),
                        field_name: member_name,
                        type_name,
                        value: None,
                    }),
                    is_static: true,
                }),
            }
        }
    }

    fn parse_js_new_member_value(&mut self, mut parts: Vec<String>) -> Result<DslValue, String> {
        if parts.len() < 2 || parts.pop().as_deref() != Some("$new") {
            return Err(self.err("expected Class.$new(...)"));
        }
        let class_name = parts.join(".");
        self.expect_char('(')?;
        let (ctor_sig, args) = self.parse_new_constructor_args()?;
        self.expect_char(')')?;
        Ok(DslValue::NewObject {
            class_name,
            ctor_sig,
            args,
        })
    }

    fn parse_js_overload_member_value(&mut self, mut parts: Vec<String>) -> Result<DslValue, String> {
        if parts.len() < 3 || parts.last().map(|part| part.as_str()) != Some("overload") {
            return Err(self.err("expected member.overload(...)"));
        }
        parts.pop();
        let call_kind = if parts.last().map(|part| part.as_str()) == Some("interface") {
            parts.pop();
            DslCallKind::Interface
        } else {
            DslCallKind::Virtual
        };
        let member_name = parts.pop().unwrap();

        self.expect_char('(')?;
        self.skip_ws();
        let mut overload_args = Vec::new();
        if self.peek() != Some(')') {
            loop {
                overload_args.push(self.parse_string_arg()?);
                if self.peek() != Some(',') {
                    break;
                }
                self.expect_char(',')?;
                self.skip_ws();
            }
        }
        self.expect_char(')')?;
        self.skip_ws();
        self.expect_char('(')?;
        let args = self.parse_value_arg_list_until_close()?;
        self.expect_char(')')?;

        if parts.len() == 1 && parse_target_name(&parts[0]).is_some() {
            let target = parse_target_name(&parts[0]).unwrap();
            let (class_name, params) = if call_kind == DslCallKind::Interface {
                let Some(class_name) = overload_args.first() else {
                    return Err(self.err("interface overload expects overload(\"InterfaceClass\", ...)"));
                };
                if class_name.starts_with('(') {
                    return Err(self.err("interface overload expects overload(\"InterfaceClass\", ...)"));
                }
                let params = if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
                    overload_args[1].clone()
                } else {
                    let param_types = overload_args[1..]
                        .iter()
                        .map(|arg| java_class_to_descriptor_or_primitive(arg))
                        .collect::<Result<Vec<_>, _>>()?;
                    build_params_sig(&param_types)
                };
                (Some(class_name.clone()), params)
            } else if overload_args.first().map(|arg| arg.starts_with('(')).unwrap_or(false) {
                (None, overload_args[0].clone())
            } else if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
                (Some(overload_args[0].clone()), overload_args[1].clone())
            } else {
                let first_is_explicit_class = matches!(target, DslTarget::Last | DslTarget::Result)
                    && overload_args.len() >= 2
                    && overload_args[0].contains('.');
                if first_is_explicit_class {
                    let param_types = overload_args[1..]
                        .iter()
                        .map(|arg| java_class_to_descriptor_or_primitive(arg))
                        .collect::<Result<Vec<_>, _>>()?;
                    (Some(overload_args[0].clone()), build_params_sig(&param_types))
                } else {
                    let param_types = overload_args
                        .iter()
                        .map(|arg| java_class_to_descriptor_or_primitive(arg))
                        .collect::<Result<Vec<_>, _>>()?;
                    (None, build_params_sig(&param_types))
                }
            };
            Ok(DslValue::Call(DslCallStmt {
                kind: call_kind,
                target: Some(target),
                receiver: None,
                null_safe: false,
                class_name,
                method_name: member_name,
                sig: params,
                args,
            }))
        } else {
            if call_kind == DslCallKind::Interface {
                return Err(self.err("interface overload requires an instance target"));
            }
            let params = if overload_args.first().map(|arg| arg.starts_with('(')).unwrap_or(false) {
                if overload_args.len() != 1 {
                    return Err(self.err("static full-signature overload expects overload(\"sig\")"));
                }
                overload_args[0].clone()
            } else {
                let param_types = overload_args
                    .iter()
                    .map(|arg| java_class_to_descriptor_or_primitive(arg))
                    .collect::<Result<Vec<_>, _>>()?;
                build_params_sig(&param_types)
            };
            Ok(DslValue::Call(DslCallStmt {
                kind: DslCallKind::Static,
                target: None,
                receiver: None,
                null_safe: false,
                class_name: Some(parts.join(".")),
                method_name: member_name,
                sig: params,
                args,
            }))
        }
    }

    fn parse_js_condition(&mut self) -> Result<DslCondition, String> {
        self.parse_js_or_condition()
    }

    fn parse_js_if_condition(&mut self) -> Result<DslCondition, String> {
        let checkpoint = self.pos;
        if let Ok(value) = self.parse_value_arg() {
            self.skip_ws();
            if self.peek() == Some(')') {
                return Ok(value.into_bool_condition());
            }
        }
        self.pos = checkpoint;

        let condition = self.parse_js_condition()?;
        self.skip_ws();
        if self.peek() == Some('?') {
            self.expect_char('?')?;
            let then_value = self.parse_value_arg()?;
            self.expect_char(':')?;
            let else_value = self.parse_value_arg()?;
            return Ok(fold_ternary(condition, then_value, else_value).into_bool_condition());
        }
        Ok(condition)
    }

    fn parse_js_or_condition(&mut self) -> Result<DslCondition, String> {
        let mut condition = self.parse_js_and_condition()?;
        loop {
            self.skip_ws();
            if !self.peek_op("||") {
                break;
            }
            self.expect_op("||")?;
            let right = self.parse_js_and_condition()?;
            condition = condition_or(condition, right);
        }
        Ok(condition)
    }

    fn parse_js_and_condition(&mut self) -> Result<DslCondition, String> {
        let mut condition = self.parse_js_unary_condition()?;
        loop {
            self.skip_ws();
            if !self.peek_op("&&") {
                break;
            }
            self.expect_op("&&")?;
            let right = self.parse_js_unary_condition()?;
            condition = condition_and(condition, right);
        }
        Ok(condition)
    }

    fn parse_js_unary_condition(&mut self) -> Result<DslCondition, String> {
        self.skip_ws();
        if self.peek() == Some('!') {
            self.expect_char('!')?;
            return Ok(condition_not(self.parse_js_unary_condition()?));
        }
        if self.peek() == Some('(') {
            self.expect_char('(')?;
            let condition = self.parse_js_condition()?;
            self.expect_char(')')?;
            return Ok(condition);
        }
        self.parse_js_condition_leaf()
    }

    fn parse_js_condition_leaf(&mut self) -> Result<DslCondition, String> {
        let left = self.parse_non_ternary_value_arg()?;
        self.skip_ws();
        if self.peek_ident("instanceof") {
            self.expect_ident("instanceof")?;
            let class_name = self.parse_type_name()?;
            return Ok(DslCondition::InstanceOf {
                value: left,
                class_name,
            });
        }
        if !self.peek_js_cmp_op() {
            if let DslValue::Bool(value) = left {
                return Ok(DslCondition::Const(value));
            }
            return Ok(DslCondition::Bool { value: left });
        }
        let op = self.parse_js_cmp_op()?;
        let right = self.parse_non_ternary_value_arg()?;
        let left_is_null = matches!(left, DslValue::Null);
        let right_is_null = matches!(right, DslValue::Null);
        if right_is_null {
            return match op {
                IfCmpOp::Eq => Ok(DslCondition::Null {
                    value: left,
                    invert: false,
                }),
                IfCmpOp::Ne => Ok(DslCondition::Null {
                    value: left,
                    invert: true,
                }),
                _ => Err(self.err("null condition only supports == and !=")),
            };
        }
        if left_is_null {
            return match op {
                IfCmpOp::Eq => Ok(DslCondition::Null {
                    value: right,
                    invert: false,
                }),
                IfCmpOp::Ne => Ok(DslCondition::Null {
                    value: right,
                    invert: true,
                }),
                _ => Err(self.err("null condition only supports == and !=")),
            };
        }
        Ok(DslCondition::Cmp { op, left, right })
    }

    fn parse_value_arg_list_until_close(&mut self) -> Result<Vec<DslValue>, String> {
        let mut args = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(')') {
                break;
            }
            args.push(self.parse_value_arg()?);
            self.skip_ws();
            if self.peek() != Some(',') {
                break;
            }
            self.expect_char(',')?;
        }
        Ok(args)
    }

    fn parse_js_cmp_op(&mut self) -> Result<IfCmpOp, String> {
        self.skip_ws();
        if self.peek_op("==") {
            self.expect_op("==")?;
            Ok(IfCmpOp::Eq)
        } else if self.peek_op("!=") {
            self.expect_op("!=")?;
            Ok(IfCmpOp::Ne)
        } else if self.peek_op("<=") {
            self.expect_op("<=")?;
            Ok(IfCmpOp::Le)
        } else if self.peek_op(">=") {
            self.expect_op(">=")?;
            Ok(IfCmpOp::Ge)
        } else if self.peek() == Some('<') {
            self.pos += 1;
            Ok(IfCmpOp::Lt)
        } else if self.peek() == Some('>') {
            self.pos += 1;
            Ok(IfCmpOp::Gt)
        } else {
            Err(self.err("expected comparison operator"))
        }
    }

    fn peek_js_cmp_op(&mut self) -> bool {
        self.skip_ws();
        self.peek_op("==")
            || self.peek_op("!=")
            || self.peek_op("<=")
            || self.peek_op(">=")
            || self.peek() == Some('<')
            || self.peek() == Some('>')
    }

    fn parse_optional_value_args(&mut self) -> Result<Vec<DslValue>, String> {
        let mut args = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() != Some(',') {
                break;
            }
            self.expect_char(',')?;
            args.push(self.parse_value_arg()?);
        }
        Ok(args)
    }

    fn expect_eof(&self) -> Result<(), String> {
        if self.pos == self.tokens.len() {
            Ok(())
        } else {
            Err(self.err("unexpected trailing input"))
        }
    }

    fn peek(&self) -> Option<char> {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::Symbol(ch)) => Some(*ch),
            _ => None,
        }
    }

    fn peek_string(&self) -> bool {
        matches!(
            self.tokens.get(self.pos).map(|token| &token.kind),
            Some(DslTokenKind::String(_))
        )
    }

    fn peek_number(&self) -> bool {
        matches!(
            self.tokens.get(self.pos).map(|token| &token.kind),
            Some(DslTokenKind::Number(_))
        )
    }

    fn peek_op(&self, expected: &str) -> bool {
        matches!(self.tokens.get(self.pos).map(|token| &token.kind), Some(DslTokenKind::Op(value)) if *value == expected)
    }

    fn expect_op(&mut self, expected: &str) -> Result<(), String> {
        if self.peek_op(expected) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(&format!("expected operator {}", expected)))
        }
    }

    fn is_eof(&self) -> bool {
        self.pos == self.tokens.len()
    }

    fn err(&self, msg: &str) -> String {
        let byte = self
            .tokens
            .get(self.pos)
            .map(|token| token.byte)
            .unwrap_or_else(|| self.input.len());
        format!("managed dex DSL parse error at byte {}: {}", byte, msg)
    }
}

fn is_ident_start(ch: char) -> bool {
    ch == '$' || ch == '_' || ch.is_ascii_alphabetic()
}

fn is_ident_continue(ch: char) -> bool {
    ch == '$' || ch == '_' || ch.is_ascii_alphanumeric()
}

fn parse_target_name(name: &str) -> Option<DslTarget> {
    match name {
        "this" | "$this" => Some(DslTarget::This),
        "last" | "$last" => Some(DslTarget::Last),
        "result" | "$result" => Some(DslTarget::Result),
        value if value.starts_with("arg") => value[3..].parse::<usize>().ok().map(DslTarget::Arg),
        value if value.starts_with('$') => value[1..].parse::<usize>().ok().map(DslTarget::Arg),
        value if value.starts_with('p') => value[1..].parse::<usize>().ok().map(DslTarget::Arg),
        value if is_local_ident(value) => Some(DslTarget::Local(value.to_string())),
        _ => None,
    }
}

fn looks_like_type_name(value: &str) -> bool {
    matches!(
        value,
        "boolean" | "byte" | "char" | "short" | "int" | "long" | "float" | "double" | "void"
    ) || matches!(value, "Z" | "B" | "C" | "S" | "I" | "J" | "F" | "D" | "V")
        || value.starts_with('[')
        || (value.starts_with('L') && value.ends_with(';'))
        || value.ends_with("[]")
        || value.contains('.')
        || value.contains('/')
}

fn looks_like_static_class_name(value: &str) -> bool {
    value.chars().next().map(|ch| ch.is_ascii_uppercase()).unwrap_or(false)
}

fn fold_unary_op(op: DslUnaryOp, value: DslValue) -> DslValue {
    match (op, value) {
        (DslUnaryOp::Neg, DslValue::Int(value)) => {
            value
                .checked_neg()
                .map(DslValue::Int)
                .unwrap_or_else(|| DslValue::UnaryOp {
                    op,
                    value: Box::new(DslValue::Int(value)),
                })
        }
        (DslUnaryOp::BitNot, DslValue::Int(value)) => DslValue::Int(!value),
        (DslUnaryOp::BoolNot, DslValue::Bool(value)) => DslValue::Bool(!value),
        (op, value) => DslValue::UnaryOp {
            op,
            value: Box::new(value),
        },
    }
}

fn fold_int_binop(op: DslIntBinOp, left: DslValue, right: DslValue) -> DslValue {
    let (DslValue::Int(left_value), DslValue::Int(right_value)) = (&left, &right) else {
        return simplify_int_binop(op, left, right);
    };
    let Some(folded) = eval_const_int_binop(op, *left_value as i32, *right_value as i32) else {
        return simplify_int_binop(op, left, right);
    };
    if folded < i16::MIN as i32 || folded > i16::MAX as i32 {
        return simplify_int_binop(op, left, right);
    }
    DslValue::Int(folded as i16)
}

fn simplify_int_binop(op: DslIntBinOp, left: DslValue, right: DslValue) -> DslValue {
    let left_int = value_int_literal(&left);
    let right_int = value_int_literal(&right);
    match op {
        DslIntBinOp::Add => {
            if right_int == Some(0) {
                return left;
            }
            if left_int == Some(0) {
                return right;
            }
        }
        DslIntBinOp::Sub => {
            if right_int == Some(0) {
                return left;
            }
            if left_int == Some(0) {
                return fold_unary_op(DslUnaryOp::Neg, right);
            }
        }
        DslIntBinOp::Mul => {
            if right_int == Some(1) {
                return left;
            }
            if left_int == Some(1) {
                return right;
            }
        }
        DslIntBinOp::Div => {
            if right_int == Some(1) {
                return left;
            }
        }
        DslIntBinOp::And => {
            if right_int == Some(-1) {
                return left;
            }
            if left_int == Some(-1) {
                return right;
            }
        }
        DslIntBinOp::Or | DslIntBinOp::Xor => {
            if right_int == Some(0) {
                return left;
            }
            if left_int == Some(0) {
                return right;
            }
        }
        DslIntBinOp::Shl | DslIntBinOp::Shr | DslIntBinOp::Ushr => {
            if right_int == Some(0) {
                return left;
            }
        }
        DslIntBinOp::Rem => {}
    }
    DslValue::IntBinOp {
        op,
        left: Box::new(left),
        right: Box::new(right),
    }
}

fn value_int_literal(value: &DslValue) -> Option<i16> {
    let DslValue::Int(value) = value else {
        return None;
    };
    Some(*value)
}

fn eval_const_int_binop(op: DslIntBinOp, left: i32, right: i32) -> Option<i32> {
    let value = match op {
        DslIntBinOp::Add => left.wrapping_add(right),
        DslIntBinOp::Sub => left.wrapping_sub(right),
        DslIntBinOp::Mul => left.wrapping_mul(right),
        DslIntBinOp::Div => {
            if right == 0 {
                return None;
            }
            left.wrapping_div(right)
        }
        DslIntBinOp::Rem => {
            if right == 0 {
                return None;
            }
            left.wrapping_rem(right)
        }
        DslIntBinOp::And => left & right,
        DslIntBinOp::Or => left | right,
        DslIntBinOp::Xor => left ^ right,
        DslIntBinOp::Shl => left.wrapping_shl((right & 0x1f) as u32),
        DslIntBinOp::Shr => left.wrapping_shr((right & 0x1f) as u32),
        DslIntBinOp::Ushr => ((left as u32).wrapping_shr((right & 0x1f) as u32)) as i32,
    };
    Some(value)
}

fn is_local_ident(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if first == '$' {
        return false;
    }
    first == '_' || first.is_ascii_alphabetic()
}
