//! crash/panic 处理模块 - 安装信号处理器和 panic hook

use crate::communication::{log_msg, write_stream_raw};
use libc::{
    c_char, c_int, c_void, sigaction, siginfo_t, SA_ONSTACK, SA_SIGINFO, SIGABRT, SIGBUS, SIGFPE,
    SIGILL, SIGSEGV, SIGTRAP,
};
use std::ffi::CStr;
use std::mem::zeroed;
use std::process;

#[cfg(feature = "frida-gum")]
use frida_gum::ModuleMap;

/// 内存映射信息
struct MapEntry {
    start: usize,
    end: usize,
    name: String,
}

/// 根据地址查找所属的映射
fn find_map_for_addr(addr: usize, maps: &[MapEntry]) -> Option<&MapEntry> {
    maps.iter().find(|m| addr >= m.start && addr < m.end)
}

/// 判断是否是 memfd（agent 代码）
fn is_memfd(name: &String) -> bool {
    name.contains("memfd:")
}

// _Unwind_Backtrace 相关定义
type UnwindReasonCode = c_int;
type UnwindContext = c_void;

extern "C" {
    fn _Unwind_Backtrace(
        trace_fn: extern "C" fn(*mut UnwindContext, *mut c_void) -> UnwindReasonCode,
        data: *mut c_void,
    ) -> UnwindReasonCode;
    fn _Unwind_GetIP(ctx: *mut UnwindContext) -> usize;
}

/// dladdr 返回的符号信息结构体
#[repr(C)]
struct DlInfo {
    dli_fname: *const c_char, // 包含地址的共享库路径
    dli_fbase: *mut c_void,   // 共享库的基地址
    dli_sname: *const c_char, // 最近符号的名称
    dli_saddr: *mut c_void,   // 最近符号的地址
}

extern "C" {
    fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int;
}

/// 使用 dladdr 解析地址的符号信息
fn resolve_symbol(addr: usize) -> (Option<String>, Option<String>, usize) {
    unsafe {
        let mut info: DlInfo = zeroed();
        if dladdr(addr as *const c_void, &mut info) != 0 {
            // 获取库名
            let lib_name = if !info.dli_fname.is_null() {
                CStr::from_ptr(info.dli_fname)
                    .to_str()
                    .ok()
                    .map(|s| s.rsplit('/').next().unwrap_or(s).to_string())
            } else {
                None
            };

            // 获取符号名
            let sym_name = if !info.dli_sname.is_null() {
                CStr::from_ptr(info.dli_sname)
                    .to_str()
                    .ok()
                    .map(|s| s.to_string())
            } else {
                None
            };

            // 计算相对偏移（相对于库基址或符号地址）
            let offset = if !info.dli_saddr.is_null() {
                addr.saturating_sub(info.dli_saddr as usize)
            } else if !info.dli_fbase.is_null() {
                addr.saturating_sub(info.dli_fbase as usize)
            } else {
                0
            };

            (lib_name, sym_name, offset)
        } else {
            (None, None, 0)
        }
    }
}

struct BacktraceData {
    frames: Vec<usize>,
    max_frames: usize,
}

extern "C" fn unwind_callback(ctx: *mut UnwindContext, data: *mut c_void) -> UnwindReasonCode {
    unsafe {
        let bt_data = &mut *(data as *mut BacktraceData);
        if bt_data.frames.len() >= bt_data.max_frames {
            return 5; // _URC_END_OF_STACK
        }
        let ip = _Unwind_GetIP(ctx);
        if ip != 0 {
            bt_data.frames.push(ip);
        }
        0 // _URC_NO_REASON (continue)
    }
}

/// 使用 _Unwind_Backtrace 获取调用栈
fn collect_backtrace() -> Vec<usize> {
    let mut data = BacktraceData {
        frames: Vec::with_capacity(64),
        max_frames: 64,
    };
    unsafe {
        _Unwind_Backtrace(unwind_callback, &mut data as *mut _ as *mut c_void);
    }
    data.frames
}

/// abort_msg_t 结构体，与 bionic 中的定义一致
#[repr(C)]
struct AbortMsgT {
    size: usize,
    // msg[0] 紧随其后，是变长字符数组
}

/// 获取 Android abort message
/// Android bionic 在 abort() 时会将消息存储在 __abort_message
fn get_abort_message() -> Option<String> {
    unsafe {
        let libc_name = std::ffi::CString::new("libc.so").ok()?;
        let handle = libc::dlopen(libc_name.as_ptr(), libc::RTLD_NOLOAD);
        if handle.is_null() {
            return None;
        }

        // 方法1：尝试使用 android_get_abort_message() API (API 21+)
        let api_name = std::ffi::CString::new("android_get_abort_message").ok()?;
        let api_ptr = libc::dlsym(handle, api_name.as_ptr());

        if !api_ptr.is_null() {
            let get_abort_msg: extern "C" fn() -> *const c_char = std::mem::transmute(api_ptr);
            let msg_ptr = get_abort_msg();
            libc::dlclose(handle);
            if !msg_ptr.is_null() {
                let c_str = CStr::from_ptr(msg_ptr);
                return c_str.to_str().ok().map(|s| s.to_string());
            }
            return None;
        }

        // 方法2：直接读取 __abort_message 全局变量
        let sym_name = std::ffi::CString::new("__abort_message").ok()?;
        let ptr = libc::dlsym(handle, sym_name.as_ptr());
        libc::dlclose(handle);

        if ptr.is_null() {
            return None;
        }

        // __abort_message 是 abort_msg_t** 类型（全局变量的地址）
        let msg_ptr_ptr = ptr as *const *const AbortMsgT;
        let msg_ptr = *msg_ptr_ptr;

        if msg_ptr.is_null() {
            return None;
        }

        let msg_size = (*msg_ptr).size;
        if msg_size == 0 {
            return None;
        }

        // msg 字符串紧跟在 size 字段之后
        let msg_data = (msg_ptr as *const u8).add(std::mem::size_of::<usize>()) as *const c_char;
        let c_str = CStr::from_ptr(msg_data);
        c_str.to_str().ok().map(|s| s.to_string())
    }
}

/// 从 ucontext 提取 ARM64 寄存器状态
unsafe fn dump_registers(ucontext: *mut c_void) -> String {
    if ucontext.is_null() {
        return "  (ucontext is NULL)\n".to_string();
    }
    // ucontext_t on aarch64-linux-android (bionic):
    //   uc_flags(8) + uc_link(8) + uc_stack(24) + uc_sigmask(8) + __padding(120) = 168
    //   + 8 bytes alignment padding → mcontext_t at offset 176
    //   mcontext_t (struct sigcontext):
    //     fault_address(8) + regs[31](248) + sp(8) + pc(8) + pstate(8)
    let uc = ucontext as *const u8;
    let mctx = 176usize; // mcontext_t offset in ucontext_t
    let regs = uc.add(mctx + 8) as *const u64; // regs[0..31]
    let sp = *(uc.add(mctx + 256) as *const u64); // sp
    let pc = *(uc.add(mctx + 264) as *const u64); // pc
    let pstate = *(uc.add(mctx + 272) as *const u64); // pstate

    let mut s = String::new();
    // PC with symbol resolution
    let (pc_lib, pc_sym, pc_off) = resolve_symbol(pc as usize);
    s.push_str(&format!("  PC:  0x{:016x}", pc));
    match (pc_lib, pc_sym) {
        (Some(lib), Some(sym)) => s.push_str(&format!(" ({} {}+0x{:x})", lib, sym, pc_off)),
        (Some(lib), None) => s.push_str(&format!(" ({} +0x{:x})", lib, pc_off)),
        _ => {}
    }
    s.push('\n');
    s.push_str(&format!("  SP:  0x{:016x}  PSTATE: 0x{:x}\n", sp, pstate));

    // x0-x30 in rows of 4
    for row in 0..8 {
        for col in 0..4 {
            let i = row * 4 + col;
            if i > 30 {
                break;
            }
            s.push_str(&format!("  x{:<2}=0x{:016x}", i, *regs.add(i)));
        }
        s.push('\n');
    }
    s
}

unsafe fn extract_pc_from_ucontext(ucontext: *mut c_void) -> Option<usize> {
    if ucontext.is_null() {
        return None;
    }
    let uc = ucontext as *const u8;
    let mctx = 176usize;
    Some(*(uc.add(mctx + 264) as *const u64) as usize)
}

unsafe fn dump_code_bytes(addr: usize, label: &str) -> String {
    if addr == 0 {
        return String::new();
    }

    let start = addr.saturating_sub(32);
    let mut s = String::new();
    s.push_str(&format!("\n=== {} BYTES ===\n", label));

    for line_start in (start..start + 64).step_by(16) {
        s.push_str(&format!("  0x{line_start:016x}:"));
        for i in 0..16 {
            let cur = line_start + i;
            let byte = *(cur as *const u8);
            s.push_str(&format!(" {:02x}", byte));
        }
        if addr >= line_start && addr < line_start + 16 {
            s.push_str("  <==");
        }
        s.push('\n');
    }

    s
}

/// 信号处理函数 - 打印崩溃信息和backtrace
extern "C" fn crash_signal_handler(sig: c_int, info: *mut siginfo_t, ucontext: *mut c_void) {
    unsafe {
        let sig_name = match sig {
            SIGSEGV => "SIGSEGV (Segmentation Fault)",
            SIGBUS => "SIGBUS (Bus Error)",
            SIGABRT => "SIGABRT (Abort)",
            SIGFPE => "SIGFPE (Floating Point Exception)",
            SIGILL => "SIGILL (Illegal Instruction)",
            SIGTRAP => "SIGTRAP (Trap)",
            _ => "Unknown signal",
        };

        let fault_addr = if !info.is_null() {
            (*info).si_addr() as usize
        } else {
            0
        };

        // 构建崩溃信息
        let mut crash_msg = format!(
            "\n\n=== CRASH DETECTED ===\n\
             Signal: {} ({})\n\
             Fault Address: 0x{:x}\n\
             PID: {}\n\
             TID: {}\n",
            sig_name,
            sig,
            fault_addr,
            process::id(),
            libc::gettid()
        );

        // 如果是 SIGABRT，尝试获取 abort message
        if sig == SIGABRT {
            if let Some(abort_msg) = get_abort_message() {
                crash_msg.push_str(&format!("Abort Message: {}\n", abort_msg));
            }
        }

        // 打印寄存器状态
        crash_msg.push_str("\n=== REGISTERS ===\n");
        crash_msg.push_str(&dump_registers(ucontext));

        if let Some(pc) = extract_pc_from_ucontext(ucontext) {
            crash_msg.push_str(&dump_code_bytes(pc, "PC"));
        }
        crash_msg.push_str("\n=== BACKTRACE ===\n");

        // 使用 _Unwind_Backtrace 获取调用栈
        let frames = collect_backtrace();

        #[cfg(feature = "frida-gum")]
        {
            // 解析内存映射（需要 frida-gum）
            let mut mdmap = ModuleMap::new();
            mdmap.update();

            for (idx, &addr) in frames.iter().enumerate() {
                crash_msg.push_str(&format!("#{:<3} 0x{:016x}", idx, addr));

                if let Some(map) = mdmap.find(addr as u64) {
                    let offset = addr - map.range().base_address().0 as usize;
                    let mdname = map.name();
                    if is_memfd(&mdname) {
                        crash_msg.push_str(&format!(" (memfd+0x{:x})", offset));
                    } else {
                        let lib_name = mdname.rsplit('/').next().unwrap_or(mdname.as_str());
                        crash_msg.push_str(&format!(" {} +0x{:x}", lib_name, offset));
                    }
                } else {
                    crash_msg.push_str(" <unknown mapping>");
                }
                crash_msg.push('\n');
            }
        }

        #[cfg(not(feature = "frida-gum"))]
        {
            // 使用 dladdr 获取符号信息
            for (idx, &addr) in frames.iter().enumerate() {
                crash_msg.push_str(&format!("#{:<3} 0x{:016x}", idx, addr));

                let (lib_name, sym_name, offset) = resolve_symbol(addr);

                match (lib_name, sym_name) {
                    (Some(lib), Some(sym)) => {
                        if is_memfd(&lib) {
                            crash_msg.push_str(&format!(" (memfd) {}+0x{:x}", sym, offset));
                        } else {
                            crash_msg.push_str(&format!(" {} ({}+0x{:x})", lib, sym, offset));
                        }
                    }
                    (Some(lib), None) => {
                        if is_memfd(&lib) {
                            crash_msg.push_str(&format!(" (memfd+0x{:x})", offset));
                        } else {
                            crash_msg.push_str(&format!(" {} +0x{:x}", lib, offset));
                        }
                    }
                    _ => {
                        crash_msg.push_str(" <unknown>");
                    }
                }
                crash_msg.push('\n');
            }
        }

        crash_msg.push_str("=== END BACKTRACE ===\n\n");

        // 尝试通过 socket 发送
        write_stream_raw(crash_msg.as_bytes());

        // 重新抛出信号以便系统处理
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// 安装崩溃信号处理器
pub(crate) fn install_crash_handlers() {
    let signals = [SIGSEGV, SIGBUS, SIGABRT, SIGFPE, SIGILL, SIGTRAP];

    for &sig in &signals {
        unsafe {
            let mut sa: sigaction = std::mem::zeroed();
            sa.sa_sigaction = crash_signal_handler as usize;
            sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
            libc::sigemptyset(&mut sa.sa_mask);

            if sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
                log_msg(format!("Failed to install handler for signal {}\n", sig));
            }
        }
    }

    // log_msg("Crash signal handlers installed\n".to_string());
}

/// 安装Rust panic hook，捕获panic并输出带符号的backtrace
pub(crate) fn install_panic_hook() {
    use std::backtrace::Backtrace;

    std::panic::set_hook(Box::new(|panic_info| {
        // 强制捕获backtrace，无视环境变量
        let bt = Backtrace::force_capture();

        // 获取panic位置
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());

        // 获取panic消息
        let payload = panic_info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| {
                panic_info
                    .payload()
                    .downcast_ref::<String>()
                    .map(|s| s.as_str())
            })
            .unwrap_or("unknown panic");

        let msg = format!(
            "\n\n=== RUST PANIC ===\n\
             Location: {}\n\
             Message: {}\n\
             PID: {}, TID: {}\n\n\
             Backtrace:\n{}\n\
             =================\n\n",
            location,
            payload,
            process::id(),
            unsafe { libc::gettid() },
            bt
        );

        log_msg(msg);
    }));
}
