use super::ffi;
use std::ffi::CStr;

pub struct LuaState {
    L: *mut ffi::lua_State,
}

impl LuaState {
    pub fn new() -> Option<Self> {
        let L = unsafe { ffi::luaL_newstate() };
        if L.is_null() {
            return None;
        }
        unsafe {
            ffi::luaL_openlibs(L);
        }
        Some(LuaState { L })
    }

    pub fn as_ptr(&self) -> *mut ffi::lua_State {
        self.L
    }

    pub unsafe fn load_bytecode(&self, bytecode: &[u8], name: &str) -> Result<(), String> {
        let cname = std::ffi::CString::new(name).unwrap();
        let ret = ffi::luaL_loadbufferx(
            self.L,
            bytecode.as_ptr() as *const _,
            bytecode.len(),
            cname.as_ptr(),
            std::ptr::null(),
        );
        if ret != ffi::LUA_OK as i32 {
            let err = self.pop_error();
            return Err(err);
        }
        Ok(())
    }

    pub unsafe fn load_string(&self, code: &str, name: &str) -> Result<(), String> {
        let cname = std::ffi::CString::new(name).unwrap();
        let ret = ffi::luaL_loadbufferx(
            self.L,
            code.as_ptr() as *const _,
            code.len(),
            cname.as_ptr(),
            std::ptr::null(),
        );
        if ret != ffi::LUA_OK as i32 {
            let err = self.pop_error();
            return Err(err);
        }
        Ok(())
    }

    pub unsafe fn pcall(&self, nargs: i32, nresults: i32) -> Result<(), String> {
        let ret = ffi::lua_pcall(self.L, nargs, nresults, 0);
        if ret != ffi::LUA_OK as i32 {
            let err = self.pop_error();
            return Err(err);
        }
        Ok(())
    }

    pub unsafe fn dostring(&self, code: &str) -> Result<(), String> {
        self.load_string(code, "<eval>")?;
        self.pcall(0, 0)
    }

    pub unsafe fn dump_function(&self) -> Result<Vec<u8>, String> {
        if !ffi::lua_isfunction_ex(self.L, -1) {
            return Err("top of stack is not a function".to_string());
        }
        let mut buf: Vec<u8> = Vec::new();
        unsafe extern "C" fn writer(
            _L: *mut ffi::lua_State,
            p: *const std::ffi::c_void,
            sz: usize,
            ud: *mut std::ffi::c_void,
        ) -> std::os::raw::c_int {
            let buf = &mut *(ud as *mut Vec<u8>);
            let slice = std::slice::from_raw_parts(p as *const u8, sz);
            buf.extend_from_slice(slice);
            0
        }
        let ret = ffi::lua_dump(self.L, Some(writer), &mut buf as *mut Vec<u8> as *mut _, 0);
        if ret != 0 {
            return Err("lua_dump failed".to_string());
        }
        Ok(buf)
    }

    pub unsafe fn set_global(&self, name: &str) {
        let cname = std::ffi::CString::new(name).unwrap();
        ffi::lua_setglobal(self.L, cname.as_ptr());
    }

    pub unsafe fn get_global(&self, name: &str) -> i32 {
        let cname = std::ffi::CString::new(name).unwrap();
        ffi::lua_getglobal(self.L, cname.as_ptr())
    }

    pub unsafe fn register_fn(&self, name: &str, f: ffi::lua_CFunction) {
        ffi::lua_pushcfunction(self.L, f);
        self.set_global(name);
    }

    unsafe fn pop_error(&self) -> String {
        let s = ffi::lua_tostring_ex(self.L, -1);
        let err = if !s.is_null() {
            CStr::from_ptr(s).to_string_lossy().into_owned()
        } else {
            "unknown Lua error".to_string()
        };
        ffi::lua_pop(self.L, 1);
        err
    }
}

impl Drop for LuaState {
    fn drop(&mut self) {
        if !self.L.is_null() {
            unsafe { ffi::lua_close(self.L) };
        }
    }
}

unsafe impl Send for LuaState {}
