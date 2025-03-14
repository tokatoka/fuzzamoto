use std::os::raw::{c_char, c_uchar};

unsafe extern "C" {
    pub fn nyx_init() -> usize;
    pub fn nyx_get_fuzz_input(data: *const c_uchar, max_size: usize) -> usize;
    pub fn nyx_skip();
    pub fn nyx_release();
    pub fn nyx_fail(message: *const c_char);
}
