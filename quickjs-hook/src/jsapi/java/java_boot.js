// Java.use() API — Frida-compatible syntax for Java method hooking
// Evaluated at engine init after C-level Java.hook/unhook/_methods/_getFieldAuto are registered.
(function() {
    "use strict";
    var _hook = Java.hook;
    var _unhook = Java.unhook;
    var _methods = Java._methods;
    var _invokeStaticMethod = Java._invokeStaticMethod;
    var _newObject = Java._newObject;
    var _getFieldAuto = Java._getFieldAuto;
    var _classLoaders = Java._classLoaders;
    var _findClassWithLoader = Java._findClassWithLoader;
    var _setClassLoader = Java._setClassLoader;
    delete Java.hook;
    delete Java.unhook;
    delete Java._methods;
    delete Java._invokeStaticMethod;
    delete Java._newObject;
    delete Java._getFieldAuto;
    delete Java._classLoaders;
    delete Java._findClassWithLoader;
    delete Java._setClassLoader;

    function _argsFrom(argsLike, start) {
        var args = [];
        for (var i = start || 0; i < argsLike.length; i++) {
            args.push(argsLike[i]);
        }
        return args;
    }

    function _isWrappedJavaObject(value) {
        return value !== null && typeof value === "object"
            && value.__jptr !== undefined;
    }

    function _wrapJavaReturn(value) {
        if (_isWrappedJavaObject(value)) {
            return _wrapJavaObj(value.__jptr, value.__jclass);
        }
        return value;
    }

    function _invokeJavaMethod(jptr, jcls, name, sig, args) {
        return _wrapJavaReturn(
            Java._invokeMethod.apply(Java, [jptr, jcls, name, sig].concat(args))
        );
    }

    function _invokeJavaStaticMethod(jcls, name, sig, args) {
        return _wrapJavaReturn(
            _invokeStaticMethod.apply(Java, [jcls, name, sig].concat(args))
        );
    }

    // 简单的 JNI 签名解析，将 "(IILjava/lang/String;)V" → ["I","I","Ljava/lang/String;"]
    function _parseJniParams(jniSig) {
        var res = [];
        var start = jniSig.indexOf('(') + 1;
        var i = start;
        while (i < jniSig.length && jniSig[i] !== ')') {
            var end = i + 1;
            if (jniSig[i] === 'L') {
                while (end < jniSig.length && jniSig[end] !== ';') end++;
                end++;
            } else if (jniSig[i] === '[') {
                while (end < jniSig.length && jniSig[end] === '[') end++;
                if (end < jniSig.length && jniSig[end] === 'L') {
                    end++;
                    while (end < jniSig.length && jniSig[end] !== ';') end++;
                    end++;
                } else {
                    end++;
                }
            }
            res.push(jniSig.slice(i, end));
            i = end;
        }
        return res;
    }

    // 判断 JS 值是否可传给 JNI 类型，同时返回匹配精度分数。
    // 返回: -1 = 不兼容, 1 = autobox 兜底, 2 = 兼容, 3 = 精确匹配
    function _scoreParam(jsVal, jniType) {
        var t0 = jniType.charAt(0);
        if (jsVal === null || jsVal === undefined) {
            return (t0 === 'L' || t0 === '[') ? 2 : -1;
        }
        var jt = typeof jsVal;
        // 引用类型: 任何 JS 值都可通过 autobox 传给引用类型参数
        if (t0 === 'L' || t0 === '[') {
            if (t0 === '[') {
                // 数组: Array 或 object 精确匹配，其余不兼容
                return (Array.isArray(jsVal) || jt === "object") ? 2 : -1;
            }
            // L 引用类型
            if (jt === "string") return jniType === "Ljava/lang/String;" ? 3 : 1;
            if (jt === "number") {
                // 精确包装类型(3) > 兼容数值类型(2) > 泛型Object(1)
                var numBoxed = {
                    "Ljava/lang/Integer;":3, "Ljava/lang/Double;":3,
                    "Ljava/lang/Float;":2, "Ljava/lang/Long;":2,
                    "Ljava/lang/Short;":2, "Ljava/lang/Byte;":2,
                    "Ljava/lang/Number;":2, "Ljava/lang/Character;":2
                };
                return numBoxed[jniType] || 1;
            }
            if (jt === "boolean") return jniType === "Ljava/lang/Boolean;" ? 3 : 1;
            if (jt === "bigint") {
                return jniType === "Ljava/lang/Long;" ? 3
                     : (jniType === "Ljava/lang/Integer;" || jniType === "Ljava/lang/Number;" ? 2 : 1);
            }
            if (jt === "object") return 2;
            return 1; // 兜底: 其他 JS 类型 → Object
        }
        // 原始类型: 只有匹配的 JS 类型才兼容
        if (t0 === 'Z') return (jt === "boolean" || jt === "number") ? 3 : -1;
        if (t0 === 'B' || t0 === 'S' || t0 === 'I' || t0 === 'F' || t0 === 'D')
            return jt === "number" ? 3 : -1;
        if (t0 === 'J') return (jt === "bigint" || jt === "number") ? 3 : -1;
        if (t0 === 'C') return jt === "string" ? 3 : (jt === "number" ? 2 : -1);
        return -1;
    }

    function _isJsValueCompatible(jsVal, jniType) {
        return _scoreParam(jsVal, jniType) >= 0;
    }

    function _scoreOverload(methodInfo, jsArgs) {
        var paramTypes = _parseJniParams(methodInfo.sig);
        if (paramTypes.length !== jsArgs.length) {
            return -1;
        }

        var score = 0;
        for (var i = 0; i < paramTypes.length; i++) {
            var s = _scoreParam(jsArgs[i], paramTypes[i]);
            if (s < 0) return -1;
            score += s;
        }
        return score;
    }

    function _resolveInstanceMethodSig(jcls, name, jsArgs) {
        var methods = _methods(jcls);
        var best = null;
        var bestScore = -1;

        for (var i = 0; i < methods.length; i++) {
            var methodInfo = methods[i];
            if (methodInfo.name !== name || methodInfo.static) {
                continue;
            }
            var score = _scoreOverload(methodInfo, jsArgs);
            if (score > bestScore) {
                best = methodInfo;
                bestScore = score;
            }
        }

        if (!best) {
            throw new Error("No instance method found: " + jcls + "." + name);
        }
        if (bestScore < 0) {
            throw new Error("No matching overload for " + jcls + "." + name
                + " with " + jsArgs.length + " argument(s)");
        }
        return best.sig;
    }

    function _resolveStaticMethodSig(jcls, name, jsArgs) {
        var methods = _methods(jcls);
        var best = null;
        var bestScore = -1;

        for (var i = 0; i < methods.length; i++) {
            var methodInfo = methods[i];
            if (methodInfo.name !== name || !methodInfo.static) {
                continue;
            }
            var score = _scoreOverload(methodInfo, jsArgs);
            if (score > bestScore) {
                best = methodInfo;
                bestScore = score;
            }
        }

        if (!best) {
            throw new Error("No static method found: " + jcls + "." + name);
        }
        if (bestScore < 0) {
            throw new Error("No matching static overload for " + jcls + "." + name
                + " with " + jsArgs.length + " argument(s)");
        }
        return best.sig;
    }

    function _resolveConstructorSig(jcls, jsArgs) {
        var methods = _methods(jcls);
        var best = null;
        var bestScore = -1;

        for (var i = 0; i < methods.length; i++) {
            var methodInfo = methods[i];
            if (methodInfo.name !== "<init>") {
                continue;
            }
            var score = _scoreOverload(methodInfo, jsArgs);
            if (score > bestScore) {
                best = methodInfo;
                bestScore = score;
            }
        }

        if (!best) {
            throw new Error("No constructor found: " + jcls);
        }
        if (bestScore < 0) {
            throw new Error("No matching constructor for " + jcls
                + " with " + jsArgs.length + " argument(s)");
        }
        return best.sig;
    }

    function _makeInstanceMethodInvoker(target, name) {
        return function() {
            var args = _argsFrom(arguments);
            var sig = typeof args[0] === "string" && args[0].charAt(0) === '('
                ? args.shift()
                : _resolveInstanceMethodSig(target.__jclass, name, args);

            return _invokeJavaMethod(
                target.__jptr,
                target.__jclass,
                name,
                sig,
                args
            );
        };
    }

    // Wrap a raw Java object pointer as a Proxy for field access via dot notation,
    // and direct instance method invocation via obj.method(...)
    // - 字段访问:   obj.fieldName
    // - 方法调用:
    //     1) 显式签名: obj.method("(Ljava/lang/String;)V", "arg")
    //     2) Frida 风格自动匹配: obj.method("arg") （根据实参类型选择 overload）
    // - 快捷调用:   obj.$call("methodName", "(sig)", ...args)
    function _wrapJavaObj(ptr, cls) {
        var target = {__jptr: ptr, __jclass: cls};
        // 缓存方法名集合（lazy init），用于快速判断 prop 是方法还是字段
        var _methodNames = null;
        function hasMethod(name) {
            if (_methodNames === null) {
                _methodNames = {};
                try {
                    var ms = _methods(cls);
                    for (var i = 0; i < ms.length; i++) {
                        if (!ms[i].static) _methodNames[ms[i].name] = true;
                    }
                } catch(e) { /* ignore */ }
            }
            return _methodNames[name] === true;
        }
        var handler = {
            get: function(target, prop) {
                if (prop === "__jptr") return target.__jptr;
                if (prop === "__jclass") return target.__jclass;
                if (prop === Symbol.toPrimitive) return function(hint) {
                    if (hint === "string" || hint === "default") {
                        try {
                            return String(_invokeJavaMethod(target.__jptr, target.__jclass, "toString", "()Ljava/lang/String;", []));
                        } catch(e) {}
                    }
                    return "[JavaObject:" + target.__jclass + "@" + target.__jptr + "]";
                };
                if (typeof prop !== "string") return undefined;
                if (prop === "toString") return function() {
                    // 调用 Java 的 toString() 方法获取有意义的字符串表示
                    try {
                        return _invokeJavaMethod(target.__jptr, target.__jclass, "toString", "()Ljava/lang/String;", []);
                    } catch(e) {
                        return "[JavaObject:" + target.__jclass + "]";
                    }
                };
                if (prop === "valueOf") return function() {
                    return "[JavaObject:" + target.__jclass + "@" + target.__jptr + "]";
                };
                if (prop === "$className") return target.__jclass;
                if (prop === "$call") {
                    return function(name, sig) {
                        if (typeof name !== "string" || typeof sig !== "string") {
                            throw new Error("obj.$call(name, sig, ...args) requires (string, string, ...)");
                        }
                        return _invokeJavaMethod(
                            target.__jptr,
                            target.__jclass,
                            name,
                            sig,
                            _argsFrom(arguments, 2)
                        );
                    };
                }
                var jptr = target.__jptr;
                var jcls = target.__jclass;

                // 方法优先：如果存在同名实例方法，返回方法调用器。
                // 避免 ArrayList.size 字段覆盖 size() 方法等冲突。
                if (hasMethod(prop)) {
                    return _makeInstanceMethodInvoker(target, prop);
                }

                // 无同名方法：尝试字段访问
                var result;
                try {
                    result = _getFieldAuto(jptr, jcls, prop);
                } catch(e) {
                    return undefined;
                }
                if (result !== undefined) {
                    return _wrapJavaReturn(result);
                }

                // 字段也没有：兜底返回方法调用器（可能是继承方法不在 _methods 列表中）
                return _makeInstanceMethodInvoker(target, prop);
            }
        };
        return new Proxy(target, handler);
    }

    function MethodWrapper(cls, method, sig, cache) {
        this._c = cls;
        this._m = method;
        this._s = sig || null;
        this._cache = cache || null;
    }

    // Convert Java type name to JNI type descriptor (mirrors Rust java_type_to_jni)
    function _jniType(t) {
        switch(t) {
            case "void": case "V": return "V";
            case "boolean": case "Z": return "Z";
            case "byte": case "B": return "B";
            case "char": case "C": return "C";
            case "short": case "S": return "S";
            case "int": case "I": return "I";
            case "long": case "J": return "J";
            case "float": case "F": return "F";
            case "double": case "D": return "D";
            default:
                if (t.charAt(0) === '[') return t.replace(/\./g, "/");
                return "L" + t.replace(/\./g, "/") + ";";
        }
    }

    // 获取方法列表（带缓存）
    function _getMethods(wrapper) {
        if (wrapper._cache && wrapper._cache.methods) return wrapper._cache.methods;
        var ms = _methods(wrapper._c);
        if (wrapper._cache) wrapper._cache.methods = ms;
        return ms;
    }

    // 根据参数签名前缀查找匹配的方法
    function _findOverload(ms, name, paramSig) {
        for (var i = 0; i < ms.length; i++) {
            if (ms[i].name === name && ms[i].sig.indexOf(paramSig) === 0) {
                return ms[i].sig;
            }
        }
        return null;
    }

    // Frida-compatible overload: accepts Java type names as arguments
    // e.g. .overload("java.lang.String", "int") → matches JNI sig "(Ljava/lang/String;I)..."
    // Also accepts raw JNI signature: .overload("(Ljava/lang/String;)I")
    // Also accepts arrays for multiple overloads: .overload(["int","int"], ["java.lang.String"])
    MethodWrapper.prototype.overload = function() {
        // Case 1: 数组语法，选择多个overload
        // .overload(["int", "int"], ["java.lang.String"])
        if (arguments.length >= 1 && Array.isArray(arguments[0])) {
            var ms = _getMethods(this);
            var name = this._m === "$init" ? "<init>" : this._m;
            var sigs = [];
            for (var a = 0; a < arguments.length; a++) {
                var params = arguments[a];
                var paramSig = "(";
                for (var i = 0; i < params.length; i++) {
                    paramSig += _jniType(params[i]);
                }
                paramSig += ")";
                var sig = _findOverload(ms, name, paramSig);
                if (!sig) {
                    throw new Error("No matching overload: " + this._c + "." + this._m + paramSig);
                }
                sigs.push(sig);
            }
            return new MethodWrapper(this._c, this._m, sigs, this._cache);
        }
        // Case 2: 原始JNI签名
        if (arguments.length === 1 && typeof arguments[0] === "string"
            && arguments[0].charAt(0) === '(') {
            return new MethodWrapper(this._c, this._m, arguments[0], this._cache);
        }
        // Case 3: Java类型名（现有行为）
        var paramSig = "(";
        for (var i = 0; i < arguments.length; i++) {
            paramSig += _jniType(arguments[i]);
        }
        paramSig += ")";
        var ms = _getMethods(this);
        var name = this._m === "$init" ? "<init>" : this._m;
        var sig = _findOverload(ms, name, paramSig);
        if (!sig) {
            throw new Error("No matching overload: " + this._c + "." + this._m + paramSig);
        }
        return new MethodWrapper(this._c, this._m, sig, this._cache);
    };

    Object.defineProperty(MethodWrapper.prototype, "impl", {
        get: function() { return this._fn || null; },
        set: function(fn) {
            var name = this._m === "$init" ? "<init>" : this._m;
            var cls = this._c;

            // 确定要hook的签名列表
            var sigs;
            if (this._s === null) {
                // 未指定overload：hook所有overload
                var ms = _getMethods(this);
                var match = [];
                for (var i = 0; i < ms.length; i++) {
                    if (ms[i].name === name) match.push(ms[i]);
                }
                if (match.length === 0)
                    throw new Error("Method not found: " + cls + "." + this._m);
                sigs = match.map(function(m) { return m.sig; });
            } else if (Array.isArray(this._s)) {
                // 通过数组语法指定的多个overload
                sigs = this._s;
            } else {
                // 单个overload
                sigs = [this._s];
            }

            if (fn === null || fn === undefined) {
                for (var i = 0; i < sigs.length; i++) {
                    _unhook(cls, name, sigs[i]);
                }
                this._fn = null;
            } else {
                var userFn = fn;
                var wrapCallback = function(ctx) {
                    if (ctx.thisObj !== undefined) {
                        ctx.thisObj = _wrapJavaObj(ctx.thisObj, cls);
                    }
                    if (ctx.args) {
                        for (var i = 0; i < ctx.args.length; i++) {
                            var a = ctx.args[i];
                            if (a !== null && typeof a === "object"
                                && a.__jptr !== undefined) {
                                ctx.args[i] = _wrapJavaObj(a.__jptr, a.__jclass);
                            }
                        }
                    }
                    // Wrap orig so returned objects auto-convert to JS Proxy
                    var origCallOriginal = ctx.orig;
                    ctx.orig = function() {
                        var ret = origCallOriginal.apply(ctx, arguments);
                        if (ret !== null && typeof ret === "object"
                            && ret.__jptr !== undefined) {
                            return _wrapJavaObj(ret.__jptr, ret.__jclass);
                        }
                        return ret;
                    };
                    return userFn(ctx);
                };
                for (var i = 0; i < sigs.length; i++) {
                    _hook(cls, name, sigs[i], wrapCallback);
                }
                this._fn = fn;
            }
        }
    });

    function _invokeStaticWrapper(wrapper, argsLike) {
        var args = _argsFrom(argsLike);
        var sig;

        if (wrapper._s === null) {
            sig = typeof args[0] === "string" && args[0].charAt(0) === '('
                ? args.shift()
                : _resolveStaticMethodSig(wrapper._c, wrapper._m, args);
        } else if (Array.isArray(wrapper._s)) {
            throw new Error("Cannot invoke multiple overloads at once: "
                + wrapper._c + "." + wrapper._m);
        } else {
            sig = wrapper._s;
        }

        return _invokeJavaStaticMethod(
            wrapper._c,
            wrapper._m === "$init" ? "<init>" : wrapper._m,
            sig,
            args
        );
    }

    function _invokeConstructorWrapper(wrapper, argsLike) {
        var args = _argsFrom(argsLike);
        var sig;

        if (wrapper._s === null) {
            sig = typeof args[0] === "string" && args[0].charAt(0) === '('
                ? args.shift()
                : _resolveConstructorSig(wrapper._c, args);
        } else if (Array.isArray(wrapper._s)) {
            throw new Error("Cannot invoke multiple constructor overloads at once: "
                + wrapper._c + "." + wrapper._m);
        } else {
            sig = wrapper._s;
        }

        return _wrapJavaReturn(
            _newObject.apply(Java, [wrapper._c, sig].concat(args))
        );
    }

    function _bindMethodWrapper(wrapper) {
        var callable = function() {
            if (wrapper._m === "$init") {
                return _invokeConstructorWrapper(wrapper, arguments);
            }
            return _invokeStaticWrapper(wrapper, arguments);
        };

        callable.overload = function() {
            return _bindMethodWrapper(MethodWrapper.prototype.overload.apply(wrapper, arguments));
        };

        Object.defineProperty(callable, "impl", {
            get: function() {
                return wrapper.impl;
            },
            set: function(fn) {
                wrapper.impl = fn;
            },
            enumerable: true,
            configurable: true
        });

        return callable;
    }

    Java.use = function(cls) {
        var cache = {};
        var wrappers = {};
        return new Proxy({}, {
            get: function(_, prop) {
                if (typeof prop !== "string") return undefined;
                if (prop === "$new") {
                    if (!cache._new) {
                        cache._new = function() {
                            var args = _argsFrom(arguments);
                            var sig = typeof args[0] === "string" && args[0].charAt(0) === '('
                                ? args.shift()
                                : _resolveConstructorSig(cls, args);
                            return _wrapJavaReturn(
                                _newObject.apply(Java, [cls, sig].concat(args))
                            );
                        };
                    }
                    return cache._new;
                }
                if (!wrappers[prop]) {
                    wrappers[prop] = _bindMethodWrapper(new MethodWrapper(cls, prop, null, cache));
                }
                return wrappers[prop];
            },
            ownKeys: function(_) {
                if (cache._ownKeys) return cache._ownKeys;
                var ms = _methods(cls);
                var seen = {};
                var keys = [];
                keys.push("$new");
                for (var i = 0; i < ms.length; i++) {
                    var n = ms[i].name === "<init>" ? "$init" : ms[i].name;
                    if (!seen[n]) { seen[n] = true; keys.push(n); }
                }
                cache._ownKeys = keys;
                return keys;
            },
            getOwnPropertyDescriptor: function(_, prop) {
                if (typeof prop !== "string") return undefined;
                return {enumerable: true, configurable: true};
            }
        });
    };

    // ========================================================================
    // Java.ready(fn) — 延迟到 app dex 加载后执行
    //
    // spawn 模式下脚本在 setArgV0 阶段加载，此时 app ClassLoader 还未创建，
    // FindClass 只能找到 framework 类。Java.ready() 通过 hook 框架类
    // Instrumentation.newApplication (ClassLoader 作为第一个参数传入) 来检测
    // dex 加载完成，在 Application.attachBaseContext 之前触发用户回调。
    //
    // 非 spawn 模式（attach 已运行的进程）时 ClassLoader 已就绪，立即执行。
    // ========================================================================
    var _readyCallbacks = [];
    var _readyFired = false;
    var _readyGateSig = "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Context;)Landroid/app/Application;";

    Java.ready = function(fn) {
        if (typeof fn !== "function") {
            throw new Error("Java.ready() requires a function argument");
        }

        // ClassLoader 已就绪（非 spawn / 已触发过），立即执行
        if (_readyFired || Java._isClassLoaderReady()) {
            _readyFired = true;
            fn();
            return;
        }

        // 首个注册：安装 gate hook
        if (_readyCallbacks.length === 0) {
            _hook("android/app/Instrumentation", "newApplication", _readyGateSig, function(ctx) {
                // 先执行原始 newApplication。stealth2/recomp 下如果在编译方法入口
                // offset 0 就触发 FindClass/WalkStack，ART 可能在 GetDexPc/StackMap
                // 路径上看到当前 quick frame native_pc=0 并 abort。
                // 将 ClassLoader 更新和 ready 回调后置，避开“当前被 hook 编译帧”
                // 仍停在入口 PC 的窗口。
                var app = ctx.orig();

                // 从第一个参数获取 ClassLoader 并更新缓存
                if (ctx.args && ctx.args[0] !== null && ctx.args[0] !== undefined) {
                    var clPtr = ctx.args[0];
                    if (typeof clPtr === "object" && clPtr.__jptr !== undefined) {
                        clPtr = clPtr.__jptr;
                    }
                    Java._updateClassLoader(clPtr);
                }

                // 执行所有排队的回调 — 用户可在此安装 hook
                // 注意：用户可能重新 hook newApplication，所以先保存 orig 引用
                _readyFired = true;
                var cbs = _readyCallbacks;
                _readyCallbacks = [];
                for (var i = 0; i < cbs.length; i++) {
                    try {
                        cbs[i]();
                    } catch(e) {
                        console.log("[Java.ready] callback #" + i + " error: " + e);
                    }
                }

                return app;
            });
        }

        _readyCallbacks.push(fn);
    };

    Java.classLoaders = function() {
        return _classLoaders();
    };

    function _normalizeLoaderArg(loader) {
        if (loader !== null && typeof loader === "object") {
            if (loader.ptr !== undefined) {
                return loader.ptr;
            }
            if (loader.__jptr !== undefined) {
                return loader.__jptr;
            }
        }
        return loader;
    }

    Java.findClassWithLoader = function(loader, className) {
        if (typeof className !== "string") {
            throw new Error("Java.findClassWithLoader(loader, className) requires a string className");
        }
        return _findClassWithLoader(_normalizeLoaderArg(loader), className);
    };

    Java.setClassLoader = function(loader) {
        return _setClassLoader(_normalizeLoaderArg(loader));
    };
})();
