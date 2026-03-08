//! agent 端 socket 通信模块

use std::io::Write;
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, OnceLock};

/// Write-half of the agent↔host socket, protected by Mutex to serialize messages
pub static GLOBAL_STREAM: OnceLock<Mutex<UnixStream>> = OnceLock::new();
pub static GLOBAL_STREAM_FD: OnceLock<i32> = OnceLock::new();

/// Write `data` to the global socket stream, serialized via Mutex.
pub(crate) fn write_stream(data: &[u8]) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = m.lock().unwrap_or_else(|e| e.into_inner()).write_all(data);
    }
}

/// 直接通过原始 fd 写 socket，供崩溃处理等场景使用。
pub(crate) fn write_stream_raw(data: &[u8]) {
    if let Some(fd) = GLOBAL_STREAM_FD.get() {
        let mut offset = 0usize;
        while offset < data.len() {
            let wrote = unsafe {
                libc::write(
                    *fd,
                    data[offset..].as_ptr() as *const libc::c_void,
                    data.len() - offset,
                )
            };
            if wrote <= 0 {
                break;
            }
            offset += wrote as usize;
        }
    }
}

pub(crate) static CACHE_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// 日志函数：socket未连接时缓存，已连接时直接发送
/// 自动添加 [agent] 前缀
pub(crate) fn log_msg(msg: String) {
    let prefixed = format!("[agent] {}", msg);
    if GLOBAL_STREAM.get().is_some() {
        write_stream(prefixed.as_bytes());
    } else {
        // Socket未连接，缓存日志
        if let Ok(mut cache) = CACHE_LOG.lock() {
            cache.push(prefixed);
        }
    }
}

/// 关闭 socket 连接，通知 host 收到 EOF 自然退出
pub(crate) fn shutdown_stream() {
    if let Some(m) = GLOBAL_STREAM.get() {
        if let Ok(stream) = m.lock() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

pub(crate) fn register_stream_fd(stream: &UnixStream) {
    let _ = GLOBAL_STREAM_FD.set(stream.as_raw_fd());
}

/// 刷新缓存的日志，在socket连接后调用
pub(crate) fn flush_cached_logs() {
    if GLOBAL_STREAM.get().is_some() {
        if let Ok(mut cache) = CACHE_LOG.lock() {
            for msg in cache.drain(..) {
                write_stream(msg.as_bytes());
            }
        }
    }
}
