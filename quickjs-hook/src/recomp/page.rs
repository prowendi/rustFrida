//! Recomp 页管理回调桥

use std::sync::Mutex;

type RecompHandler = fn(usize) -> Result<usize, String>;
type RecompAllocSlotHandler = fn(usize) -> Result<usize, String>;
type RecompFixupHandler = fn(*mut u8, usize) -> Result<(), String>;
type RecompCommitHandler = fn(usize) -> Result<(), String>;

static HANDLER: Mutex<Option<RecompHandler>> = Mutex::new(None);
static ALLOC_SLOT_HANDLER: Mutex<Option<RecompAllocSlotHandler>> = Mutex::new(None);
static FIXUP_HANDLER: Mutex<Option<RecompFixupHandler>> = Mutex::new(None);
static COMMIT_HANDLER: Mutex<Option<RecompCommitHandler>> = Mutex::new(None);

pub fn set_handler(handler: RecompHandler) {
    *HANDLER.lock().unwrap() = Some(handler);
}

pub fn set_alloc_slot_handler(handler: RecompAllocSlotHandler) {
    *ALLOC_SLOT_HANDLER.lock().unwrap() = Some(handler);
}

pub fn set_fixup_handler(handler: RecompFixupHandler) {
    *FIXUP_HANDLER.lock().unwrap() = Some(handler);
}

pub fn set_commit_handler(handler: RecompCommitHandler) {
    *COMMIT_HANDLER.lock().unwrap() = Some(handler);
}

static REVERT_HANDLER: Mutex<Option<RecompCommitHandler>> = Mutex::new(None);

pub fn set_revert_handler(handler: RecompCommitHandler) {
    *REVERT_HANDLER.lock().unwrap() = Some(handler);
}

/// 恢复 recomp 代码页上被 B 覆盖的原始指令（unhook 时调用）
pub fn revert_slot_patch(orig_addr: usize) -> Result<(), String> {
    let guard = REVERT_HANDLER.lock().unwrap();
    let handler = match guard.as_ref() {
        Some(h) => h,
        None => return Ok(()), // 非 recomp 模式，静默返回
    };
    handler(orig_addr)
}

pub fn ensure_and_translate(orig_addr: usize) -> Result<usize, String> {
    let guard = HANDLER.lock().unwrap();
    let handler = match guard.as_ref() {
        Some(h) => h,
        None => return Err("recomp handler not set".into()),
    };
    handler(orig_addr)
}

/// 分配 recomp 跳板 slot + 写 B 指令到 recomp 代码页
pub fn alloc_trampoline_slot(orig_addr: usize) -> Result<usize, String> {
    let guard = ALLOC_SLOT_HANDLER.lock().unwrap();
    let handler = match guard.as_ref() {
        Some(h) => h,
        None => return Err("recomp alloc_slot handler not set".into()),
    };
    handler(orig_addr)
}

/// 在 recomp 代码页上写 B→slot（原子提交，thunk 已就绪后调用）
pub fn commit_slot_patch(orig_addr: usize) -> Result<(), String> {
    let guard = COMMIT_HANDLER.lock().unwrap();
    let handler = match guard.as_ref() {
        Some(h) => h,
        None => return Err("recomp commit handler not set".into()),
    };
    handler(orig_addr)
}

/// 修复 hook engine 为 slot 生成的 trampoline（用 recomp 页的真正原始指令重建）
pub fn fixup_slot_trampoline(trampoline: *mut u8, orig_addr: usize) -> Result<(), String> {
    let guard = FIXUP_HANDLER.lock().unwrap();
    let handler = match guard.as_ref() {
        Some(h) => h,
        None => return Err("recomp fixup handler not set".into()),
    };
    handler(trampoline, orig_addr)
}
