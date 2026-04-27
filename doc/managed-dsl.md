# Managed DSL

`Java.managedHookDsl` compiles hook logic into a generated dex helper and routes the
target method through the managed direct thunk. It is intended for high-frequency
Java method hooks where JS/Lua callbacks are too expensive or unstable under app
natural traffic.

## Basic Usage

```js
Java.ready(function () {
  Java.compileMethod(
    "java.util.HashMap",
    "put",
    "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
    "auto"
  );

  Java._resetArtRouteStats();

  Java.managedHookDsl({
    className: "java.util.HashMap",
    methodName: "put",
    signature: "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
    dsl:
      "let n: int = this.size();" +
      "let plus: int = n + 1;" +
      "let sb: java.lang.StringBuilder = java.lang.StringBuilder.$new(\"seed\");" +
      "if (arg0 instanceof java.lang.String) {" +
      "  let keyLen: int = (arg0 as java.lang.String).length();" +
      "  sb.append(arg0);" +
      "}" +
      "new int[](3);" +
      "let a: int[] = last;" +
      "a[0] = plus;" +
      "if (plus > 0) {" +
      "  return orig(arg0, arg1);" +
      "} else {" +
      "  return orig(arg0, arg1);" +
      "}"
  });
});
```

## High-Frequency Rules

If a DSL program uses `orig()`, every return path must end with `return orig();`
or `return orig(...)`.
The compiler rejects mixed return paths such as:

```js
"if (arg0 == null) {" +
"  return null;" +
"} else {" +
"  return orig();" +
"}"
```

This restriction is deliberate. `orig()` is routed through a generated managed
`__rf_orig` method. The helper is compiled against that normal dex call, then
the `__rf_orig` quick entrypoint is rewritten to the original-method trampoline.
Keeping `orig()` returns structurally simple avoids mixing the backup call path
with unrelated direct returns on high-frequency traffic.

`orig()` calls the original method with the original receiver and arguments.
`orig(arg0, arg1)` calls the original method with explicit replacement
arguments. The replacement argument count must exactly match the hooked method's
parameter count; instance receivers are still supplied automatically.

The expected stable stats are:

```text
managed > 0
orig=0
set=0
bypassActive=0
backup=0
```

## Supported DSL Syntax

### Locals

```js
"let n = this.size();" +
"let plus = n + 1;"
```

Local declarations can infer their type from the expression descriptor. Use an
explicit type when the expression is ambiguous or intentionally widened:

```js
"let obj: java.lang.Object = arg0;" +
"let s = arg0 as java.lang.String;"
```

### Arguments And Built-In Targets

```text
this   current receiver, only for instance methods
arg0   first Java argument
arg1   second Java argument
last   last object result produced by new/call/cast/array get
result last primitive int-like result
```

Aliases such as `$this`, `$last`, `$0`, `$1`, `p0`, and `p1` are also accepted by
the parser, but the JS-like names above are preferred.

### Constructors

```js
"new java.lang.StringBuilder(\"seed\");"
```

Constructor expression:

```js
"let sb: java.lang.StringBuilder = java.lang.StringBuilder.$new(\"seed\");"
```

For no-arg constructors:

```js
"new java.lang.StringBuilder();"
```

The new object is stored in `last`.

Full JNI constructor signatures are still accepted as a fallback:

```js
"new java.lang.StringBuilder(\"(Ljava/lang/String;)V\", \"seed\");"
```

### Method Calls

Instance call with inferred receiver:

```js
"let sb: java.lang.StringBuilder = last;" +
"sb.append(arg0);"
```

Instance call on `this`:

```js
"let n: int = this.size();"
```

Static call:

```js
"let value: int = java.lang.Integer.parseInt(\"123\");"
```

Direct calls infer the overload from the receiver type and argument descriptors.
Interface receivers emit `invoke-interface`; class receivers emit virtual,
direct, or static invoke as appropriate. If overload resolution is ambiguous or
no overload matches, the compiler reports a compile-time error and the script
should use explicit `overload(...)`.

`overload(...)` is still available for disambiguation and accepts Java parameter
type names. The return type is resolved from reflection by class + method name +
parameter list, because Java return types do not participate in overload
selection.

Full JNI signatures are still accepted when reflection cannot resolve a method:

```js
"last.append.overload(\"java.lang.StringBuilder\", \"(Ljava/lang/Object;)Ljava/lang/StringBuilder;\")(arg0);"
```

### Original Calls

Call the original method with unchanged arguments:

```js
"return orig();"
```

Call the original method with explicit arguments:

```js
"return orig(arg0, arg1);"
```

Store the original result before running more DSL logic:

```js
"let old = orig(arg0, arg1);" +
"return old;"
```

You can still write an explicit type if you want to widen the original return:

```js
"let old: java.lang.Object = orig(arg0, arg1);" +
"return old;"
```

For instance hooks, do not pass `this` to `orig(...)`; only pass Java method
parameters. For static hooks, pass all static method parameters.

### Arrays

```js
"new int[](3);" +
"let a: int[] = last;" +
"let x: int = a[0];" +
"a[1] = x + 1;"
```

Array element type is inferred from local and argument descriptors. If inference
fails, use explicit element type syntax:

```js
"let x: int = a[0: int];"
```

### Fields

Field read and write use member syntax with an explicit field type:

```js
"let n: int = this.size(\"int\");" +
"this.size(\"int\") = n + 1;"
```

For ambiguous receiver types, include the declaring class:

```js
"let n: int = this.size(\"java.util.HashMap\", \"int\");"
```

### Conditions

```js
"if (arg0 == null) {" +
"  return orig();" +
"} else {" +
"  return orig();" +
"}"
```

Supported comparisons include `==`, `!=`, `<`, `<=`, `>`, and `>=`. `null`
conditions only support `==` and `!=`.

Boolean values can be used directly as conditions. This is meant for common Java
boolean calls and fields:

```js
"if (arg0 != null && arg0.equals.overload(\"java.lang.Object\")(\"target\")) {" +
"  return orig(arg0, arg1);" +
"} else {" +
"  return orig();" +
"}"
```

Object method calls follow normal Java null semantics. Add null guards before
calling methods on arguments from natural app traffic.

`instanceof` is supported and narrows the guarded target in the true branch:

```js
"if (arg0 instanceof java.lang.String) {" +
"  let n: int = arg0.length();" +
"  return orig(arg0, arg1);" +
"} else {" +
"  return orig(arg0, arg1);" +
"}"
```

The same narrowing is available inside compound expressions and ternary
branches:

```js
"if (arg0 instanceof java.lang.String && arg0.length() > 0) {" +
"  let n: int = (arg0 instanceof java.lang.String ? arg0.length() : 0);" +
"  return orig(arg0, arg1);" +
"}" +
"return orig(arg0, arg1);"
```

Compound conditions support JS-like `&&`, `||`, `!`, and parentheses:

```js
"if ((arg0 != null && arg1 != null) || !(arg0 instanceof java.lang.String)) {" +
"  return orig();" +
"} else {" +
"  return orig();" +
"}"
```

Integer `switch` is supported with explicit blocks and automatic break:

```js
"switch (code) {" +
"  case 0: { return orig(); }" +
"  case 1: { return null; }" +
"  default: { return orig(); }" +
"}"
```

Dense integer cases compile to dex `packed-switch`; sparse cases compile to
dex `sparse-switch`.

### Casts

Use `as` for explicit object casts when the compiler cannot infer the precise
receiver type or when the code reads better with an explicit type:

```js
"if (arg0 instanceof java.lang.String) {" +
"  let n: int = (arg0 as java.lang.String).length();" +
"  return orig(arg0, arg1);" +
"}" +
"return orig(arg0, arg1);"
```

The cast compiles to dex `check-cast`; it does not cross the JS/Lua runtime
boundary.

### Returns

High-frequency orig path:

```js
"return orig();"
```

Orig result path:

```js
"let old: java.lang.Object = orig(arg0, arg1);" +
"return old;"
```

`let x = orig(...)` is intentionally restricted: it must appear once as the first
top-level statement, and it cannot be mixed with `return orig(...)`. This keeps
the backup-orig call path deterministic before any additional user DSL logic
runs.

Direct value returns are supported only for DSL programs that do not use
`orig()` or `orig(...)`:

```js
"return null;"
"return 1;"
```

### Throw

Throwing Java exceptions is supported:

```js
"throw java.lang.IllegalStateException.$new(\"java.lang.String\", \"blocked\");"
```

The emitted dex casts the value to `java.lang.Throwable` before `throw`, so
non-Throwable object values fail with normal Java cast semantics. Primitive
values cannot be thrown.

### Try / Catch

`orig(...)` is emitted as a call to a generated backup method, so exceptions can
be caught by generated dex code:

```js
"try {" +
"  return orig(arg0);" +
"} catch (java.lang.NumberFormatException e) {" +
"  return 0;" +
"}"
```

The catch variable is a typed local object and can be used inside the catch
block:

```js
"try {" +
"  return orig(arg0, arg1);" +
"} catch (java.lang.RuntimeException e) {" +
"  throw e;" +
"}"
```

## Current Limits

- `return orig(...)` cannot be mixed with `return null`, `return value`, or
  fall-through return paths on normal control flow. Catch blocks may return a
  fallback value for an exception thrown by `orig(...)`.
- `let x = orig(...)` must be the first top-level statement and cannot be nested.
- Local variable type inference uses the static descriptor of the expression.
  Use `let name: Type = value` when inference is impossible, for example `null`.
- `switch` supports integer case constants only. Case bodies must use `{ ... }`,
  and fallthrough/break are not part of the DSL.
- Loops are not part of the JS-like managed DSL.
- Only one catch handler is currently emitted per generated method.
- Monitor enter/exit and synchronized blocks are not part of the DSL.
- Complex object lifetime rules should stay inside generated managed code.
  Avoid JS/Lua callbacks on hot methods.
- Reflection-style Java APIs from JS/Lua are not the high-frequency path. Use
  managed DSL operations that compile into dex bytecode.

## JD HashMap High-Frequency Template

This is the current preferred smoke test for hot Java traffic. It exercises
direct overload inference, `instanceof` narrowing, `as` cast, and explicit
`orig(arg0, arg1)` while staying in generated dex code:

```js
Java.ready(function () {
  console.log("[managed-dsl] install HashMap.put smoke test");
  Java._resetArtRouteStats();
  Java.managedHookDsl({
    className: "java.util.HashMap",
    methodName: "put",
    signature: "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
    dsl:
      "if (arg0 instanceof java.lang.String && arg0.length() >= 0) {" +
      "  let n: int = (arg0 as java.lang.String).length();" +
      "  return orig(arg0, arg1);" +
      "}" +
      "return orig(arg0, arg1);"
  });
});
```

Run it against JD natural startup traffic and require at least 150k managed
direct hits before calling the result stable.

## Device Validation

Build and push:

```bash
cargo build --release -p agent
cargo build --release -p rust_frida
adb -s <device> push target/aarch64-linux-android/release/rustfrida /data/local/tmp/rustfrida
adb -s <device> shell "su -c 'sh -c \"chmod 755 /data/local/tmp/rustfrida\"'"
```

Run a high-frequency validation script:

```bash
({ sleep 45; \
   echo 'jseval (function(){var s=Java._artRouteStats(); return "managed="+String(s.managedDirectHits)+",orig="+String(s.origBypassHits)+",set="+String(s.origBypassSetSuccesses)+",fail="+String(s.origBypassSetFailures)+",active="+String(s.origBypassActive)+",backup="+String(s.managedBackupStubHits);})()'; \
   sleep 3; echo exit; } | timeout 80s adb -s <device> shell \
  "su -c '/data/local/tmp/rustfrida --spawn com.jingdong.app.mall -l /data/local/tmp/test_js_accept_managed_dsl_ops_orig.js'")
```

Check logcat:

```bash
adb -s <device> logcat -d -v time | rg -i \
  "ANR|not responding|SuspendAll timeout|Fatal signal|SIGABRT|SIGSEGV|DynManagedHook|managedHook"
```

Successful validation should show the route stats closed:

```text
managed=354184,orig=0,set=0,fail=0,active=0,backup=0
```

The exact count varies with app traffic. The important conditions are equal
`managed > 0`, zero orig-bypass hits/sets/failures, zero active bypass slots, no
backup stub hits, and no ANR/SuspendAll/SIGSEGV/fatal signal in logcat.

## Local Acceptance Scripts

The repository root may contain local, ignored manual scripts:

```text
test_js_accept_managed_dsl_orig_array.js
test_js_accept_managed_dsl_ops_orig.js
test_js_reject_managed_dsl_mixed_orig.js
```

They are intentionally excluded from commits by local git exclude rules because
repository policy does not commit test-related files by default.
