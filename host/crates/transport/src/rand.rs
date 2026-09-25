//! Cryptographic randomness from the OS (std-only).

use std::io::Read;

#[cfg(unix)]
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    let f = std::fs::File::open("/dev/urandom")
        .unwrap_or_else(|e| panic!("cannot open /dev/urandom: {e}"));
    f.take(n as u64)
        .read_exact(&mut out)
        .expect("urandom read failed");
    out
}

#[cfg(windows)]
pub fn random_bytes(n: usize) -> Vec<u8> {
    use std::ptr::null_mut;
    extern "system" {
        fn GetSystemRandom(hrandstate: *mut std::ffi::c_void,
                           pdata: *mut u8, cb: u32) -> i32;
    }
    let mut out = vec![0u8; n];
    let ok = unsafe { GetSystemRandom(null_mut(), out.as_mut_ptr(), n as u32) };
    assert_ne!(ok, 0, "GetSystemRandom failed");
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn unique() {
        let a = super::random_bytes(16);
        let b = super::random_bytes(16);
        assert_ne!(a, b);
    }
}
