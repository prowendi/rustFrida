#![cfg(all(target_os = "android", target_arch = "aarch64"))]

mod logger;

use clap::Parser;
use libc::{bind, listen, sleep, sockaddr_un, AF_UNIX, SOCK_STREAM};
use libc::{c_int, c_void, close, connect, free, iovec, malloc, mmap, mprotect, munmap, pid_t, pthread_create, pthread_detach, recvmsg, socket, write, PTRACE_CONT, PTRACE_GETREGSET, PTRACE_SETREGSET};
use libc::{strlen, dlopen, dlsym, dlerror, memcpy, memfd_create, snprintf, write as libc_write, MFD_CLOEXEC};
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use once_cell::unsync::Lazy;
use paste::paste;
use rustyline::Editor;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, Helper};
use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, IoSlice, Write};
use std::io::Read;
use std::mem::{size_of_val, zeroed};
use std::os::unix::io::FromRawFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Condvar, Mutex, OnceLock, RwLock};
use std::thread;
use std::thread::JoinHandle;
use std::process;

static AGENT_MEMFD: AtomicI32 = AtomicI32::new(-1);
static STOP_LISTENER: AtomicBool = AtomicBool::new(false);

/// Shared state for synchronous jscomplete request/response.
/// The Condvar is notified when the agent returns a COMPLETE: response.
static COMPLETE_RESULT: OnceLock<(Mutex<Option<Vec<String>>>, Condvar)> = OnceLock::new();

fn complete_state() -> &'static (Mutex<Option<Vec<String>>>, Condvar) {
    COMPLETE_RESULT.get_or_init(|| (Mutex::new(None), Condvar::new()))
}

/// 定义需要获取偏移的函数列表
macro_rules! define_libc_functions {
    ($($name:ident),*) => {
        #[derive(Debug, Default)]
        struct LibcOffsets {
            $($name: usize),*
        }

        impl LibcOffsets {
            fn calculate(self_base: usize, target_base: usize) -> Self {
                Self {
                    $(
                        $name: {
                            let sym_addr = $name as *const () as usize;
                            if sym_addr < self_base {
                                panic!(
                                    "符号 {} 地址(0x{:x}) 小于libc基址(0x{:x})",
                                    stringify!($name), sym_addr, self_base
                                );
                            }
                            let offset = sym_addr - self_base;
                            target_base + offset
                        }
                    ),*
                }
            }

            fn print_offsets(&self) {
                log_step!("目标进程函数地址列表:");
                $(println!("     {}: 0x{:x}", stringify!($name), self.$name);)*
            }
        }
    };
}

macro_rules! define_dl_functions {
    ($($name:ident),*) => {
        #[derive(Debug, Default)]
        struct DlOffsets {
            $($name: usize),*
        }

        impl DlOffsets {
            fn calculate(self_base: usize, target_base: usize) -> Self {
                Self {
                    $(
                        $name: {
                            let sym_addr = $name as *const () as usize;
                            if sym_addr < self_base {
                                panic!(
                                    "符号 {} 地址(0x{:x}) 小于dl基址(0x{:x})",
                                    stringify!($name), sym_addr, self_base
                                );
                            }
                            let offset = sym_addr - self_base;
                            target_base + offset
                        }
                    ),*
                }
            }

            fn print_offsets(&self) {
                log_step!("libdl.so 函数地址列表:");
                $(println!("     {}: 0x{:x}", stringify!($name), self.$name);)*
            }
        }
    };
}

// 定义字符串表宏
// 支持通过 overrides HashMap 覆盖默认值，格式：name=value
macro_rules! define_string_table {
    ($(($name:ident, $value:expr)),* $(,)?) => {
        paste! {
            #[repr(C)]
            pub struct StringTable {
                $(
                    pub $name: u64,
                    pub [<$name _len>]: u32,
                )*
            }

            // 获取所有可用的字符串名称
            fn get_string_table_names() -> Vec<&'static str> {
                vec![$(stringify!($name)),*]
            }

            #[allow(unused_assignments)]
            fn write_string_table(pid: i32, malloc_addr: usize, overrides: &std::collections::HashMap<String, String>) -> Result<usize, String> {
                $(
                    // 检查是否有覆盖值
                    let mut $name = if let Some(override_val) = overrides.get(stringify!($name)) {
                        override_val.as_bytes().to_vec()
                    } else {
                        $value.to_vec() 
                    };
                    $name.push(0); // 添加 NULL 结尾
                )*

                let strings_len = 0 $(+ $name.len())*;
                let table_size = std::mem::size_of::<StringTable>();
                let total_size = table_size + strings_len;

                // 通过 call_target_function 用目标进程的 malloc 分配内存
                let table_addr = call_target_function(pid, malloc_addr, &[total_size], None)?;
                let mut string_addr = table_addr + table_size;

                let mut table = StringTable {
                    $(
                        $name: 0,
                        [<$name _len>] : 0,
                    )*
                };

                $(
                    table.$name = string_addr as u64;
                    // 长度包含最后的 NULL 结尾
                    table.[<$name _len>] = $name.len() as u32;
                    write_bytes(pid, string_addr, &$name)?;
                    string_addr += $name.len();
                )*

                write_memory(pid, table_addr, &table)?;
                Ok(table_addr)
            }
        }
    };
}

// 使用宏定义字符串表
define_string_table!(
    (socket_name, b"rust_frida_socket"),
    (hello_msg, b"HELLO_LOADER"),
    (sym_name, b"hello_entry"),
    (pthread_err, b"pthreadded"),
    (dlsym_err, b"dlsymFail"),
    (proc_path, b"/proc/self/fd/"),
    (cmdline, b"novalue"),
    (output_path, b"novalue"),
    // 未来添加字符串只需在这里添加新行即可
);

// 使用宏定义函数列表
define_libc_functions!(
    malloc,    // 用于分配内存
    free,      // 用于释放内存
    socket,    // 用于创建套接字
    connect,   // 用于连接套接字
    write,     // 用于发送数据
    close,     // 用于关闭套接字
    mprotect,  // 用于设置内存保护
    mmap,      // 用于内存映射
    munmap,    // 用于释放内存映射
    recvmsg,    // 用于接收文件描述符
    pthread_create,
    pthread_detach,
    snprintf,    // 用于格式化字符串
    memcpy,
    strlen
);

define_dl_functions!(
    dlopen,    // 动态加载
    dlsym,      // 动态符号查找
    dlerror
);

/// 用户空间寄存器结构体
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct UserRegs {
    regs: [u64; 31],      // X0-X30 寄存器
    sp: u64,             // SP 栈指针
    pc: u64,             // PC 程序计数器
    pstate: u64,         // 处理器状态
}

/// 获取 libc 基址
/// 
/// # 参数
/// * `pid` - 进程ID，如果为 None 则获取当前进程的 libc 基址
fn get_libc_base(pid: Option<i32>) -> Result<usize, String> {
    // 构建 maps 文件路径
    let maps_path = match pid {
        Some(pid) => format!("/proc/{}/maps", pid),
        None => "/proc/self/maps".to_string(),
    };

    // 检查文件是否存在
    if !Path::new(&maps_path).exists() {
        return Err(format!("进程 {} 不存在", pid.unwrap_or(-1)));
    }

    let file = File::open(&maps_path).map_err(|e| format!("无法打开maps文件: {}", e))?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.map_err(|e| format!("读取maps文件失败: {}", e))?;
        if line.contains("libc.so") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(addr_range) = parts.get(0) {
                if let Some(start_addr) = addr_range.split('-').next() {
                    return usize::from_str_radix(start_addr, 16)
                        .map_err(|e| format!("解析地址失败: {}", e));
                }
            }
        }
    }

    Err(format!("未找到进程 {} 的libc.so加载地址", pid.unwrap_or(-1)))
}

/// 获取 libdl.so 基址
/// 
/// # 参数
/// * `pid` - 进程ID，如果为 None 则获取当前进程的 libdl.so 基址
fn get_dl_base(pid: Option<i32>) -> Result<usize, String> {
    // 构建 maps 文件路径
    let maps_path = match pid {
        Some(pid) => format!("/proc/{}/maps", pid),
        None => "/proc/self/maps".to_string(),
    };

    // 检查文件是否存在
    if !Path::new(&maps_path).exists() {
        return Err(format!("进程 {} 不存在", pid.unwrap_or(-1)));
    }

    let file = File::open(&maps_path).map_err(|e| format!("无法打开maps文件: {}", e))?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.map_err(|e| format!("读取maps文件失败: {}", e))?;
        if line.contains("libdl.so") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(addr_range) = parts.get(0) {
                if let Some(start_addr) = addr_range.split('-').next() {
                    return usize::from_str_radix(start_addr, 16)
                        .map_err(|e| format!("解析地址失败: {}", e));
                }
            }
        }
    }

    Err(format!("未找到进程 {} 的libdl.so加载地址", pid.unwrap_or(-1)))
}

fn attach_to_process(pid: i32) -> Result<(), String> {
    let target_pid = Pid::from_raw(pid);
    
    // 尝试附加到目标进程
    match ptrace::attach(target_pid) {
        Ok(_) => {
            log_success!("成功附加到进程 {}，等待 SIGSTOP...", pid);
            match waitpid(target_pid, None) {
                Ok(WaitStatus::Stopped(_, _)) => {
                    log_success!("进程已停止，可以操作寄存器");
                    Ok(())
                }
                other => Err(format!("waitpid 状态异常: {:?}", other)),
            }
        },
        Err(errno) => {
            let err_msg = match errno {
                Errno::EPERM => "权限不足，请使用root权限运行",
                Errno::ESRCH => "目标进程不存在",
                _ => "附加失败，未知错误",
            };
            Err(err_msg.to_string())
        }
    }
}

/// 获取进程寄存器
fn get_registers(pid: i32) -> Result<UserRegs, String> {
    let mut regs = UserRegs::default();
    let mut iov = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: size_of::<UserRegs>(),
    };
    let result = unsafe {
        libc::ptrace(
            PTRACE_GETREGSET,
            pid as pid_t,
            1, // 通用寄存器
            &mut iov as *mut _ as *mut c_void,
        )
    };
    
    if result == -1 {
        let errno = unsafe { *libc::__errno() };
        return Err(format!("获取寄存器失败，错误码: {}", errno));
    }
    Ok(regs)
}

/// 设置进程寄存器
fn set_registers(pid: i32, regs: &UserRegs) -> Result<(), String> {
    let mut iov = iovec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len: size_of::<UserRegs>(),
    };
    let result = unsafe {
        libc::ptrace(
            PTRACE_SETREGSET,
            pid as pid_t,
            1,
            &mut iov as *mut _ as *mut c_void,
        )
    };
    if result == -1 {
        let errno = unsafe { *libc::__errno() };
        return Err(format!("设置寄存器失败，错误码: {}", errno));
    }
    Ok(())
}

/// 调用目标进程的 libc 函数
/// 
/// # 参数
/// * `pid` - 目标进程ID
/// * `func_addr` - 要调用的函数地址
/// * `args` - 函数参数列表
/// 
/// # 返回值
/// * `Ok(usize)` - 函数返回值
/// * `Err(String)` - 错误信息
fn call_target_function(pid: i32, func_addr: usize, args: &[usize], debug: Option<bool>) -> Result<usize, String> {
    // 获取当前寄存器状态
    let orig_regs = get_registers(pid)?;
    
    // 设置新的寄存器状态
    let mut new_regs = orig_regs;
    
    // 设置参数寄存器（ARM64 使用 X0-X7 寄存器传递参数）
    for (i, &arg) in args.iter().enumerate() {
        if i < 8 {
            new_regs.regs[i] = arg as u64;
        } else {
            break;
        }
    }
    
    // 设置返回地址为 0x340
    new_regs.regs[30] = 0x340;  // X30 是链接寄存器 (LR)
    
    // 设置 PC 指向函数地址
    new_regs.pc = func_addr as u64;
    
    // 写入新寄存器值
    set_registers(pid, &new_regs)?;
    
    // 继续执行
    if debug.unwrap_or(false) {
        let _ = ptrace::cont(Pid::from_raw(pid), Some(Signal::SIGSTOP));
        process::exit(1);
    }
    let result = unsafe {
        libc::ptrace(
            PTRACE_CONT as c_int,
            pid as pid_t,
            0,
            0
        )
    };
    
    if result == -1 {
        return Err(format!("继续执行失败，错误码: {}", unsafe { *libc::__errno() }));
    }
    
    // 等待进程停止
    let target_pid = Pid::from_raw(pid);
    match waitpid(target_pid, None).map_err(|e| format!("等待进程失败: {}", e))? {
        WaitStatus::Stopped(_, Signal::SIGSEGV) => {
            // 获取寄存器，检查 PC 是否为预期值
            let regs = get_registers(pid)?;
            
            if regs.pc == 0x340 {
                // 函数执行完成，获取返回值（ARM64 使用 X0 寄存器返回值）
                let return_value = regs.regs[0] as usize;
                
                // 恢复原始寄存器状态
                set_registers(pid, &orig_regs)?;
                
                Ok(return_value)
            } else {
                Err(format!("函数执行异常，PC = 0x{:x}", regs.pc))
            }
        },
        status => Err(format!("进程异常停止: {:?}", status)),
    }
}

/// 命令行参数结构体
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 目标进程的PID（与 --watch-so 互斥）
    #[arg(short, long, required_unless_present = "watch_so")]
    pid: Option<i32>,

    /// 监听指定 SO 路径加载，自动附加到加载该 SO 的进程
    #[arg(short = 'w', long = "watch-so")]
    watch_so: Option<String>,

    /// 监听超时时间（秒），默认无限等待
    #[arg(short = 't', long = "timeout")]
    timeout: Option<u64>,

    /// 添加自定义字符串到字符串表（可多次使用）
    /// 格式: name=value 或直接指定值
    #[arg(short = 's', long = "string", value_name = "NAME=VALUE")]
    strings: Vec<String>,

    /// 加载并执行JavaScript脚本文件
    #[arg(short = 'l', long = "load-script", value_name = "FILE")]
    load_script: Option<String>,
}

fn create_memfd_with_data(name: &str, data: &[u8]) -> Result<RawFd, String> {
    let cname = CString::new(name).unwrap();
    let fd = unsafe { memfd_create(cname.as_ptr(), MFD_CLOEXEC) };
    if fd < 0 {
        return Err(format!("memfd_create 失败: {}", std::io::Error::last_os_error()));
    }
    // 写入数据
    let mut written = 0;
    while written < data.len() {
        let ret = unsafe {
            libc_write(
                fd,
                data[written..].as_ptr() as *const c_void,
                data.len() - written,
            )
        };
        if ret < 0 {
            unsafe { close(fd) };
            return Err(format!("memfd 写入失败: {}", std::io::Error::last_os_error()));
        }
        written += ret as usize;
    }
    Ok(fd)
}

fn send_fd_over_unix_socket(stream: &UnixStream, fd_to_send: RawFd) -> Result<(), String> {
    let data = b"AGENT_SO";
    let iov = [IoSlice::new(data)];
    let fds = [fd_to_send];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    let sock_fd = stream.as_raw_fd();
    sendmsg(sock_fd, &iov, &cmsg, MsgFlags::empty(), None::<&()>)
        .map_err(|e| format!("发送文件描述符失败: {}", e))?;
    Ok(())
}

static GLOBAL_SENDER: OnceLock<Sender<String>> = OnceLock::new();
static mut AGENT_STAT: Lazy<RwLock<bool>> = Lazy::new(|| RwLock::new(false));
fn handle_socket_connection(mut stream: UnixStream) {

    let mut buffer = [0; 1024];
    while let Ok(size) = stream.read(&mut buffer) {
        if size == 0 {
            break;
        }
        
        if let Ok(msg) = String::from_utf8(buffer[..size].to_vec()) {
            let trimmed = msg.trim();

            // 如果是 HELLO_LOADER，额外发送 memfd
            if trimmed == "HELLO_LOADER" {
                log_info!("{}", trimmed);
                let memfd = AGENT_MEMFD.load(Ordering::SeqCst);
                if memfd >= 0 {
                    if let Err(e) = send_fd_over_unix_socket(&stream, memfd) {
                        log_error!("发送 memfd 失败: {}", e);
                    }
                } else {
                    log_error!("memfd 无效，无法发送 agent.so");
                }
            } else if trimmed == "HELLO_AGENT" {
                log_success!("Agent 已连接");
                STOP_LISTENER.store(true, Ordering::SeqCst);
                let mut stream_clone = stream.try_clone().unwrap();
                thread::spawn(move || {
                    let (sd,rx) = channel();
                    match GLOBAL_SENDER.set(sd) {
                        Ok(_) => {},
                        Err(_) => {
                            log_error!("GLOBAL_SENDER already set!");
                            return;
                        }
                    }
                    unsafe {*(AGENT_STAT.write().unwrap()) = true;}
                    while let Ok(msg) = rx.recv() {
                        match stream_clone.write_all(msg.as_bytes()){
                            Ok(_) => {},
                            Err(e) => {
                                log_error!("stream 写入失败: {}", e);
                                break;
                            }
                        }
                    }
                });
            } else if trimmed.contains("COMPLETE:") {
                // 从消息中提取 COMPLETE: 部分（可能和其他输出混在一起）
                let complete_part = if let Some(pos) = trimmed.find("COMPLETE:") {
                    &trimmed[pos + "COMPLETE:".len()..]
                } else {
                    ""
                };
                let candidates: Vec<String> = if complete_part.is_empty() {
                    vec![]
                } else {
                    complete_part.lines().map(|s| s.to_string()).collect()
                };
                let (lock, cvar) = complete_state();
                if let Ok(mut guard) = lock.lock() {
                    *guard = Some(candidates);
                    cvar.notify_all();
                }
            } else {
                log_agent!("{}", trimmed);
            }
        }
    }
}

fn start_socket_listener(socket_path: &str) -> Result<JoinHandle<()>, Box<dyn std::error::Error>> {
    // 创建 socket
    let fd = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    // 构造 sockaddr_un，抽象socket: sun_path[0]=0, 后面跟名字
    let mut addr: sockaddr_un = unsafe { zeroed() };
    addr.sun_family = AF_UNIX as u16;
    let name_bytes = socket_path.as_bytes();
    let path_len = name_bytes.len().min(107); // sun_path最多108字节
    addr.sun_path[0] = 0; // 抽象socket
    addr.sun_path[1..=path_len].copy_from_slice(&name_bytes[..path_len]);
    let sockaddr_len = (size_of_val(&addr.sun_family) + 1 + path_len) as u32;

    // 绑定
    let ret = unsafe {
        bind(
            fd,
            &addr as *const _ as *const _,
            sockaddr_len,
        )
    };
    if ret < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    // 监听
    let ret = unsafe { listen(fd, 128) };
    if ret < 0 {
        return Err(Box::new(std::io::Error::last_os_error()));
    }

    // 转为 Rust 的 UnixListener，设为非阻塞以便响应停止信号
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    listener.set_nonblocking(true).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    let handle = thread::spawn(move || {
        loop {
            if STOP_LISTENER.load(Ordering::SeqCst) {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    thread::spawn(move || {
                        handle_socket_connection(stream);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => log_error!("接受连接失败: {}", e),
            }
        }
    });
    Ok(handle)
}

// 嵌入loader.bin
const SHELLCODE: &[u8] = include_bytes!("../../loader/build/loader.bin");

const AGENT_SO: &[u8] = include_bytes!("../../target/aarch64-linux-android/debug/libagent.so");

/// 向远程进程内存写入任意类型的数据
/// 
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的数据指针
/// * `size` - 数据大小（字节数）
fn write_remote_mem(pid: i32, addr: usize, data: *const u8, size: usize) -> Result<(), String> {
    // 去掉 MTE 标签位（高 byte），ptrace 不支持带标签的地址
    let addr = addr & 0x00FFFFFFFFFFFFFF;
    let mut offset = 0;
    while offset < size {
        let remaining = size - offset;
        let write_size = if remaining >= 8 { 8 } else { remaining };
        
        // 读取数据
        let mut word: u64 = 0;
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.add(offset),
                &mut word as *mut u64 as *mut u8,
                write_size
            );
        }
        
        // 写入目标进程
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_POKETEXT,
                pid as pid_t,
                (addr + offset) as *mut c_void,
                word as usize as *mut c_void,
            )
        };
        
        if result == -1 {
            let errno = unsafe { *libc::__errno() };
            return Err(format!("写入内存失败 addr=0x{:x} offset={} size={} errno={}", addr, offset, size, errno));
        }
        
        offset += write_size;
    }
    
    Ok(())
}

/// 向远程进程内存写入任意类型的数据的泛型包装
/// 
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的数据（任意类型）
fn write_memory<T>(pid: i32, addr: usize, data: &T) -> Result<(), String> {
    write_remote_mem(
        pid,
        addr,
        data as *const T as *const u8,
        size_of::<T>(),
    )
}

/// 向远程进程内存写入字节数组
///
/// # 参数
/// * `pid` - 目标进程ID
/// * `addr` - 目标地址
/// * `data` - 要写入的字节数组
fn write_bytes(pid: i32, addr: usize, data: &[u8]) -> Result<(), String> {
    write_remote_mem(
        pid,
        addr,
        data.as_ptr(),
        data.len(),
    )
}

/// 注入 agent 到目标进程
fn inject_to_process(pid: i32, string_overrides: &std::collections::HashMap<String, String>) -> Result<(), String> {
    log_info!("正在附加到进程 PID: {}", pid);

    // 获取自身和目标进程的 libc 基址
    let self_base = get_libc_base(None)?;
    let target_base = get_libc_base(Some(pid))?;
    let self_dl_base = get_dl_base(None)?;
    let target_dl_base = get_dl_base(Some(pid))?;

    log_step!("自身 libc.so 基址: 0x{:x}", self_base);
    log_step!("目标进程 libc.so 基址: 0x{:x}", target_base);
    log_step!("自身 libdl.so 基址: 0x{:x}", self_dl_base);
    log_step!("目标进程 libdl.so 基址: 0x{:x}", target_dl_base);

    // 计算目标进程中的函数地址
    let offsets = LibcOffsets::calculate(self_base, target_base);
    let dl_offsets = DlOffsets::calculate(self_dl_base, target_dl_base);

    // 打印所有函数地址
    offsets.print_offsets();
    dl_offsets.print_offsets();

    // 附加到目标进程
    attach_to_process(pid)?;
    log_info!("开始分配内存");

    // 分配内存用于shellcode
    let page_size = 4096;
    let shellcode_len = ((SHELLCODE.len() + page_size - 1) / page_size) * page_size;
    let mmap_prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    let mmap_flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    let shellcode_addr = call_target_function(
        pid,
        offsets.mmap,
        &[
            0, // addr = NULL，让内核分配
            shellcode_len,
            mmap_prot as usize,
            mmap_flags as usize,
            !0usize, // fd = -1
            0,       // offset = 0
        ], None
    ).map_err(|e| format!("调用 mmap 失败: {}", e))?;

    log_step!("分配shellcode内存");
    log_addr!("地址", shellcode_addr);

    // 写入shellcode
    write_bytes(pid, shellcode_addr, SHELLCODE)?;
    log_success!("Shellcode写入成功");
    log_addr!("地址", shellcode_addr);

    // 分配内存用于LibcOffsets结构体
    let offsets_size = size_of::<LibcOffsets>();
    let offsets_addr = call_target_function(pid, offsets.malloc, &[offsets_size], None)
        .map_err(|e| format!("分配offsets内存失败: {}", e))?;

    log_step!("分配offsets内存");
    log_addr!("地址", offsets_addr);

    // 写入LibcOffsets结构体
    write_memory(pid, offsets_addr, &offsets)?;
    log_success!("Offsets写入成功");
    log_addr!("地址", offsets_addr);

    let dloffset_size = size_of::<DlOffsets>();
    let dloffset_addr = call_target_function(pid, offsets.malloc, &[dloffset_size], None)
        .map_err(|e| format!("分配dloffsets内存失败: {}", e))?;

    log_step!("分配dloffsets内存");
    log_addr!("地址", dloffset_addr);

    // 写入DlOffsets结构体
    write_memory(pid, dloffset_addr, &dl_offsets)?;
    log_success!("DlOffsets写入成功");
    log_addr!("地址", dloffset_addr);

    // 写入字符串表
    let string_table_addr = write_string_table(pid, offsets.malloc, string_overrides)?;
    log_success!("字符串表写入成功");
    log_addr!("地址", string_table_addr);

    // 使用 call_target_function 调用 shellcode
    match call_target_function(pid, shellcode_addr, &[offsets_addr, dloffset_addr, string_table_addr], None) {
        Ok(return_value) => {
            log_success!("Shellcode 执行完成，返回值: 0x{:x}", return_value as isize);

            // 释放shellcode内存
            log_info!("正在释放shellcode内存...");
            match call_target_function(
                pid,
                offsets.munmap,
                &[shellcode_addr, shellcode_len],
                None
            ) {
                Ok(_) => log_success!("Shellcode内存释放成功"),
                Err(e) => log_error!("释放shellcode内存失败: {}", e),
            }

            // detach 目标进程
            if let Err(e) = ptrace::detach(Pid::from_raw(pid), None) {
                log_error!("分离目标进程失败: {}", e);
            } else {
                log_success!("已分离目标进程");
            }
            Ok(())
        },
        Err(e) => {
            log_error!("执行 shellcode 失败: {}", e);
            log_warn!("暂停目标进程，等待调试器附加...");
            // 发送 SIGSTOP 让目标进程暂停
            let _ = ptrace::cont(Pid::from_raw(pid), Some(Signal::SIGSTOP));
            Err(e)
        }
    }
}

/// 根据 UID 查找 /data/data/ 目录下对应的应用数据目录
fn find_data_dir_by_uid(uid: u32) -> Option<String> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    let data_dir = "/data/data";

    match fs::read_dir(data_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.uid() == uid {
                        if let Some(path) = entry.path().to_str() {
                            return Some(path.to_string());
                        }
                    }
                }
            }
            None
        }
        Err(e) => {
            log_error!("读取 /data/data 目录失败: {}", e);
            None
        }
    }
}

/// 使用 eBPF 监听 SO 加载并自动附加
fn watch_and_inject(so_pattern: &str, timeout_secs: Option<u64>, string_overrides: &std::collections::HashMap<String, String>) -> Result<(), String> {
    use ldmonitor::DlopenMonitor;
    use std::time::Duration;

    log_info!("正在启动 eBPF 监听器，等待加载: {}", so_pattern);

    let monitor = DlopenMonitor::new(None)
        .map_err(|e| format!("启动 eBPF 监听失败: {}", e))?;

    let info = if let Some(secs) = timeout_secs {
        log_step!("超时时间: {} 秒", secs);
        monitor.wait_for_path_timeout(so_pattern, Duration::from_secs(secs))
    } else {
        log_step!("无超时限制，持续监听中...");
        monitor.wait_for_path(so_pattern)
    };

    monitor.stop();

    match info {
        Some(dlopen_info) => {
            let pid = dlopen_info.pid();
            if let Some(ns_pid) = dlopen_info.ns_pid {
                if ns_pid != dlopen_info.host_pid {
                    log_success!("检测到 SO 加载: pid={} (host_pid={}), uid={}, path={}",
                        ns_pid, dlopen_info.host_pid, dlopen_info.uid, dlopen_info.path);
                } else {
                    log_success!("检测到 SO 加载: pid={}, uid={}, path={}", pid, dlopen_info.uid, dlopen_info.path);
                }
            } else {
                log_success!("检测到 SO 加载: host_pid={}, uid={}, path={}", dlopen_info.host_pid, dlopen_info.uid, dlopen_info.path);
            }

            // 克隆 string_overrides 以便修改
            let mut overrides = string_overrides.clone();

            // 根据 uid 自动检测 /data/data/ 目录
            if let Some(data_dir) = find_data_dir_by_uid(dlopen_info.uid) {
                log_step!("自动检测到应用数据目录: {}", data_dir);
                overrides.insert("output_path".to_string(), data_dir);
            } else {
                log_warn!("未能找到 uid {} 对应的 /data/data/ 目录", dlopen_info.uid);
            }

            inject_to_process(pid as i32, &overrides)
        }
        None => Err("监听超时，未检测到匹配的 SO 加载".to_string())
    }
}

/// 支持的命令列表及其说明
const COMMANDS: &[(&str, &str, &str)] = &[
    ("trace",      "[tid]",            "ptrace 指令追踪"),
    ("jhook",      "",                 "Java/JNI hooking"),
    ("stalker",    "[tid]",            "Frida Stalker 追踪"),
    ("hfl",        "<module> <offset>","Interceptor hook 指定偏移"),
    ("qfl",        "<module> <offset>","QBDI 追踪指定偏移"),
    ("jsinit",     "",                 "初始化 QuickJS 引擎"),
    ("loadjs",     "<script>",         "执行 JavaScript 代码"),
    ("jsclean",    "",                 "清理 QuickJS 引擎"),
    ("jsrepl",     "",                 "进入 JS REPL 模式（Tab 动态补全）"),
    ("help",       "",                 "显示此帮助信息"),
];

/// Tab 补全器：仅补全第一个 token（命令名）
struct CommandCompleter;

impl CommandCompleter {
    fn new() -> Self {
        CommandCompleter
    }
}

impl Completer for CommandCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // 只在光标处于第一个 token 范围内时补全
        let before_cursor = &line[..pos];
        if before_cursor.contains(' ') {
            return Ok((pos, vec![]));
        }
        let prefix = before_cursor;
        let candidates: Vec<Pair> = COMMANDS
            .iter()
            .filter(|(cmd, _, _)| cmd.starts_with(prefix))
            .map(|(cmd, _, _)| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect();
        Ok((0, candidates))
    }
}

impl Hinter for CommandCompleter {
    type Hint = String;
}
impl Highlighter for CommandCompleter {}
impl Validator for CommandCompleter {}
impl Helper for CommandCompleter {}

/// JS REPL 补全器：通过 socket 向 agent 发送 jscomplete 请求，同步等待结果。
struct JsReplCompleter {
    sender: Sender<String>,
}

impl JsReplCompleter {
    fn new(sender: Sender<String>) -> Self {
        JsReplCompleter { sender }
    }

    /// Send a jscomplete request and block until the agent replies (≤2000 ms timeout).
    fn fetch_completions(&self, prefix: &str) -> Vec<String> {
        let (lock, cvar) = complete_state();

        // 持有锁的同时 clear + send + wait，避免竞态
        let mut guard = match lock.lock() {
            Ok(g) => g,
            Err(_) => return vec![],
        };
        *guard = None;

        // Send the request
        let cmd = format!("jscomplete {}", prefix);
        if self.sender.send(cmd).is_err() {
            return vec![];
        }

        // Wait for the response (up to 2000 ms)
        // wait_timeout 会原子释放锁并等待，被唤醒后重新获取锁
        let timeout = std::time::Duration::from_millis(2000);
        let result = cvar.wait_timeout_while(guard, timeout, |val| val.is_none());
        match result {
            Ok((guard, timeout_result)) => {
                if timeout_result.timed_out() {
                    vec![]
                } else {
                    guard.clone().unwrap_or_default()
                }
            },
            Err(_) => vec![],
        }
    }
}

impl Completer for JsReplCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let before_cursor = &line[..pos];

        // Determine the replacement start position.  After the last '.' we only
        // replace the property fragment, but we send the *full* before_cursor
        // (e.g. "console.l") so the agent can resolve the object and enumerate
        // its properties.
        let (start, query) = if let Some(dot_pos) = before_cursor.rfind('.') {
            // start is right after the dot so rustyline replaces only the property part
            (dot_pos + 1, before_cursor)
        } else {
            (0, before_cursor)
        };

        let candidates: Vec<Pair> = self
            .fetch_completions(query)
            .into_iter()
            .map(|name| Pair {
                display: name.clone(),
                replacement: name,
            })
            .collect();

        Ok((start, candidates))
    }
}

impl Hinter for JsReplCompleter {
    type Hint = String;
}
impl Highlighter for JsReplCompleter {
    fn highlight_candidate<'c>(
        &self,
        candidate: &'c str,
        completion: CompletionType,
    ) -> std::borrow::Cow<'c, str> {
        if completion == CompletionType::List {
            // Dark gray background + bright white text for list-mode candidates
            std::borrow::Cow::Owned(format!("\x1b[48;5;238m\x1b[38;5;255m{}\x1b[0m", candidate))
        } else {
            std::borrow::Cow::Borrowed(candidate)
        }
    }
}
impl Validator for JsReplCompleter {}
impl Helper for JsReplCompleter {}

/// 打印命令帮助表
fn print_help() {
    use crate::logger::{BOLD, CYAN, GREEN, RESET, YELLOW, DIM};
    println!("\n{BOLD}{CYAN}可用命令:{RESET}");
    println!("{DIM}  {:<10} {:<22} {}{RESET}", "命令", "参数", "说明");
    println!("{DIM}  {:-<10} {:-<22} {:-<20}{RESET}", "", "", "");
    for (cmd, args, desc) in COMMANDS {
        println!(
            "  {BOLD}{GREEN}{:<10}{RESET} {YELLOW}{:<22}{RESET} {}",
            cmd, args, desc
        );
    }
    println!();
}

/// Enter an interactive JS REPL mode.
///
/// Every line is sent as `loadjs <line>` to the agent.  Tab completion
/// queries the live QuickJS global scope via `jscomplete`.
/// Type `exit` or press Ctrl-D / Ctrl-C to return to the main prompt.
fn run_js_repl(sender: &Sender<String>) {
    use crate::logger::{BOLD, CYAN, DIM, RESET};
    println!("\n{BOLD}{CYAN}进入 JS REPL 模式{RESET} {DIM}(输入 exit 或按 Ctrl-D 退出){RESET}\n");

    // Clone the sender so JsReplCompleter can own it
    let sender_clone = sender.clone();
    let config = Config::builder()
        .completion_type(CompletionType::List)
        .completion_prompt_limit(usize::MAX)
        .build();
    let mut rl: Editor<JsReplCompleter, _> = match Editor::with_config(config) {
        Ok(e) => e,
        Err(e) => {
            log_error!("初始化 JS REPL 行编辑器失败: {}", e);
            return;
        }
    };
    rl.set_helper(Some(JsReplCompleter::new(sender_clone)));

    loop {
        match rl.readline("js> ") {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);
                if line == "exit" || line == "quit" {
                    println!("{DIM}退出 JS REPL 模式{RESET}");
                    break;
                }
                let cmd = format!("loadjs {}", line);
                if let Err(e) = sender.send(cmd) {
                    log_error!("发送 JS 命令失败: {}", e);
                    break;
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                println!("{DIM}退出 JS REPL 模式{RESET}");
                break;
            }
            Err(e) => {
                log_error!("读取 JS REPL 输入失败: {}", e);
                break;
            }
        }
    }
}

fn main() {
    logger::print_banner();
    let args = Args::parse();

    // 初始化 agent.so 的 memfd
    match create_memfd_with_data("wwb_so", AGENT_SO) {
        Ok(fd) => {
            AGENT_MEMFD.store(fd, Ordering::SeqCst);
            log_success!("已创建 agent.so memfd: {}", fd);
        }
        Err(e) => {
            log_error!("创建 agent.so memfd 失败: {}", e);
            process::exit(1);
        }
    }

    // 启动抽象套接字监听
    let handle = start_socket_listener("rust_frida_socket");

    // 解析字符串覆盖参数（格式：name=value）
    let mut string_overrides = std::collections::HashMap::new();
    let available_names = get_string_table_names();

    for s in &args.strings {
        if let Some((name, value)) = s.split_once('=') {
            if available_names.contains(&name) {
                string_overrides.insert(name.to_string(), value.to_string());
            } else {
                log_warn!("未知的字符串名称 '{}', 可用名称: {:?}", name, available_names);
            }
        } else {
            log_warn!("无效的字符串格式 '{}', 应为 name=value", s);
        }
    }

    // 打印字符串覆盖信息
    if !string_overrides.is_empty() {
        log_info!("字符串覆盖列表 ({} 个):", string_overrides.len());
        for (name, value) in &string_overrides {
            println!("     {} = {}", name, value);
        }
    }

    // 根据参数选择注入方式
    let result = if let Some(so_pattern) = &args.watch_so {
        // 使用 eBPF 监听 SO 加载
        watch_and_inject(so_pattern, args.timeout, &string_overrides)
    } else if let Some(pid) = args.pid {
        // 直接附加到指定 PID
        if pid <= 0 {
            log_error!("PID必须是正整数");
            process::exit(1);
        }
        inject_to_process(pid, &string_overrides)
    } else {
        log_error!("必须指定 --pid 或 --watch-so");
        process::exit(1);
    };

    if let Err(e) = result {
        log_error!("注入失败: {}", e);
        process::exit(1);
    }

    unsafe {
        while *(AGENT_STAT.read().unwrap()) == false {
            sleep(1);
            log_info!("等待 agent 连接...");
        }
    }
    let sender = GLOBAL_SENDER.get().unwrap();

    // If a script file was specified, load and send it
    if let Some(script_path) = &args.load_script {
        match std::fs::read_to_string(script_path) {
            Ok(script) => {
                log_info!("加载脚本: {}", script_path);
                // First initialize the JS engine
                if let Err(e) = sender.send("jsinit".to_string()) {
                    log_error!("发送 jsinit 失败: {}", e);
                }
                // Wait a bit for initialization
                unsafe { sleep(1) };
                // Send the script
                let cmd = format!("loadjs {}", script);
                if let Err(e) = sender.send(cmd) {
                    log_error!("发送 loadjs 失败: {}", e);
                }
            }
            Err(e) => {
                log_error!("读取脚本文件 '{}' 失败: {}", script_path, e);
            }
        }
    }

    let mut rl = match Editor::new() {
        Ok(e) => e,
        Err(e) => {
            log_error!("初始化行编辑器失败: {}", e);
            process::exit(1);
        }
    };
    rl.set_helper(Some(CommandCompleter::new()));
    loop {
        match rl.readline("rustfrida> ") {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);
                if line == "help" {
                    print_help();
                    continue;
                }
                if line == "jsrepl" {
                    run_js_repl(sender);
                    continue;
                }
                match sender.send(line) {
                    Ok(_) => {},
                    Err(e) => {
                        log_error!("发送命令失败: {}", e);
                        break;
                    }
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                log_info!("退出交互模式");
                break;
            }
            Err(e) => {
                log_error!("读取输入失败: {}", e);
                break;
            }
        }
    }
    // 等待监听线程退出
    handle.unwrap().join().unwrap();

    // 清理资源
    let memfd = AGENT_MEMFD.load(Ordering::SeqCst);
    if memfd >= 0 {
        unsafe { close(memfd) };
        log_success!("已关闭 agent.so memfd");
    }
}