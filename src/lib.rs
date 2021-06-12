use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::prelude::*;
use std::path::Path;

/// Correct on every architecture except alpha (which Rust doesn't support)
const SYS_OPENAT2: libc::c_long = 437;

bitflags::bitflags! {
    /// Flags that modify path resolution.
    #[repr(transparent)]
    pub struct ResolveFlags: u64 {
        /// Block traversal of mount points (including bind mounts) during path resolution.
        const NO_XDEV = 0x01;
        /// Disallow resolution of magic links (see `symlink(7)`) during path resolution.
        const NO_MAGICLINKS = 0x02;
        /// Disallow resolution of all symbolic links during path resolution.
        const NO_SYMLINKS = 0x04;
        /// Fail if path resolution would leave the directory specified by `dirfd`.
        ///
        /// Note: This currently implies [`Self::NO_MAGICLINKS`], but that may change in the
        /// future. If your application nees to ensure that magic links are not resolved, you
        /// should explicitly specify [`Self::NO_MAGICLINKS`].
        const BENEATH = 0x08;
        /// Treat the directory specified by `dirfd` as the root directory when resolving the given
        /// path.
        ///
        /// This is similar to a temporary `chroot()` to the directory specified by `dirfd`.
        ///
        /// Note: This flag currently implies [`Self::NO_MAGICLINKS`], but that may change in the
        /// future. If your application nees to ensure that magic links are not resolved, you
        /// should explicitly specify [`Self::NO_MAGICLINKS`].
        const IN_ROOT = 0x10;
        /// Only allow the open operation to succeed if it can be done entirely with information in
        /// the kernel's lookup cache.
        ///
        /// Added in Linux 5.12.
        ///
        /// This will fail with `EAGAIN` if any kind of revalidation or I/O is needed. It may be
        /// useful for fast-path opens, with a fallback on offloading to a thread.
        const CACHED = 0x20;
    }
}

/// A structure that specifies how a path should be opened with [`openat2()`].
#[derive(Clone, Debug)]
#[non_exhaustive]
#[repr(C)]
pub struct OpenHow {
    /// The file creation and file status flags to use when opening the file.
    pub flags: u64,
    /// The mode to create the file with.
    ///
    /// If `O_CREAT` or `O_TMPFILE` is not in [`Self::flags`], this must be 0.
    pub mode: u64,
    /// Flags that modify path resolution. See [`ResolveFlags`].
    pub resolve: ResolveFlags,
}

impl OpenHow {
    /// Create a new `OpenHow` structure with the specified `flags` and `mode`.
    ///
    /// Since this structure is non-exhaustive, this is the only way to create an `OpenHow`
    /// structure. Other fields can then be modified on the returned structure.
    #[inline]
    pub fn new(flags: i32, mode: u32) -> Self {
        Self {
            flags: flags as u64,
            mode: mode as u64,
            resolve: ResolveFlags::empty(),
        }
    }

    /// Emulate the kernel's truncation of `self.flags`/`self.mode` for `open()`/`openat()`.
    ///
    /// `open()` and `openat()` will ignore `flags` that they do not recognize, and will ignore
    /// `mode` if neither `O_CREAT` nor `O_TMPFILE` was specified. `openat2()`, however, fails
    /// with `EINVAL` in these scenarios.
    ///
    /// This method will modify `self.flags` and `self.mode` such that calling `openat2()` with
    /// this `OpenHow` structure should NOT fail with `EINVAL` because those fields are invalid. It
    /// may be useful in scenarios where it is necessary to emulate the behavior of `open()` or
    /// `openat()`.
    ///
    /// # Example
    ///
    /// ```
    /// # use openat2::OpenHow;
    /// let mut how = OpenHow::new(libc::O_PATH | libc::O_WRONLY | libc::O_CLOEXEC, 0o666);
    /// how.truncate_flags_mode();
    /// // The kernel ignores all but a few `flags` (and ignores `mode` entirely) when O_PATH is
    /// // specified, so that's emulated by this function
    /// assert_eq!(how.flags, (libc::O_PATH | libc::O_CLOEXEC) as u64);
    /// assert_eq!(how.mode, 0);
    /// ```
    pub fn truncate_flags_mode(&mut self) {
        if self.flags & libc::O_PATH as u64 == libc::O_PATH as u64 {
            // Only a few `flags` work with O_PATH, and `mode` is ignored completely
            self.flags &=
                (libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
            self.mode = 0;
        } else {
            // Exhaustive list of all valid `flags`
            self.flags &= (libc::O_RDONLY
                | libc::O_WRONLY
                | libc::O_RDWR
                | libc::O_APPEND
                | libc::O_ASYNC
                | libc::O_CLOEXEC
                | libc::O_CREAT
                | libc::O_DIRECT
                | libc::O_DIRECTORY
                | libc::O_DSYNC
                | libc::O_EXCL
                | libc::O_LARGEFILE
                | libc::O_NOATIME
                | libc::O_NOCTTY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_PATH
                | libc::O_SYNC
                | libc::O_TMPFILE
                | libc::O_TRUNC) as u64;

            // `mode` is ignored except for `O_CREAT` and `O_TMPFILE`
            if self.flags & libc::O_CREAT as u64 != libc::O_CREAT as u64
                && self.flags & libc::O_TMPFILE as u64 != libc::O_TMPFILE as u64
            {
                self.mode = 0;
            }
        }
    }
}

/// Call the `openat2()` syscall to open the specified `path`.
///
/// This function converts the given `path` to a `CString` and calls [`openat2_cstr()`].
///
/// See `openat2(2)` for general information on the `openat2()` syscall.
///
/// # Notes:
///
/// - If `dirfd` is `None`, it will be translated to `AT_FDCWD` when calling the syscall.
/// - The returned file descriptor will NOT have its close-on-exec flag set by default! It is
///   recommended to include `O_CLOEXEC` in the flags specified using `how` to ensure this is set.
#[inline]
pub fn openat2<P: AsRef<Path>>(dirfd: Option<RawFd>, path: P, how: &OpenHow) -> io::Result<RawFd> {
    let path = CString::new(path.as_ref().as_os_str().as_bytes())?;
    openat2_cstr(dirfd, &path, how)
}

/// Call the `openat2()` syscall to open the specified `path`.
///
/// This is a lower-level function that is called by [`openat2()`]. See that function's
/// documentation for more details.
#[inline]
pub fn openat2_cstr(dirfd: Option<RawFd>, path: &CStr, how: &OpenHow) -> io::Result<RawFd> {
    let res = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            dirfd.unwrap_or(libc::AT_FDCWD),
            path.as_ptr(),
            how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };

    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res as RawFd)
    }
}

/// Probe for the presence of the `openat2()` syscall.
///
/// This checks if [`openat2()`] is supported on the current kernel using the most efficient method
/// possible.
///
/// Note: Use of [`has_openat2_cached()`] is recommended for most cases.
#[inline]
pub fn has_openat2() -> bool {
    match unsafe {
        libc::syscall(
            SYS_OPENAT2,
            libc::AT_FDCWD,
            std::ptr::null::<libc::c_char>(),
            std::ptr::null::<OpenHow>(),
            std::mem::size_of::<OpenHow>(),
        )
    } {
        // EFAULT is expected because of the null pointers
        -1 => unsafe { *libc::__errno_location() == libc::EFAULT },

        fd => {
            // This shouldn't happen.
            // Close the file descriptor and conservatively assume that openat2() isn't present.
            unsafe {
                libc::close(fd as _);
            }
            false
        }
    }
}

/// A cached version of [`has_openat2()`].
///
/// This is equivalent to [`has_openat2()`], except that the result is cached after the first call
/// for efficiency.
///
/// Note that the result is cached using an atomic data type, without locking. As a result, if
/// multiple threads call this function concurrently, [`has_openat2()`] may be called multiple
/// times.
#[inline]
pub fn has_openat2_cached() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};

    static HAS_OPENAT2: AtomicU8 = AtomicU8::new(2);

    match HAS_OPENAT2.load(Ordering::Relaxed) {
        0 => false,
        1 => true,

        _ => {
            let res = has_openat2();
            HAS_OPENAT2.store(res as u8, Ordering::Relaxed);
            res
        }
    }
}

/// Check whether the running kernel supports the given `OpenHow` structure.
///
/// This will return `false` if the running kernel either a) doesn't support `openat2()` or b)
/// doesn't support the given `how`.
///
/// This can be useful for probing for the kernel's support of specific flags, such as
/// [`ResolveFlags::CACHED`] (added in kernel 5.12). However, this function may be slow, so it's
/// highly recommended to cache the result to avoid repeated syscalls.
#[inline]
pub fn supports_open_how(how: &OpenHow) -> bool {
    match unsafe {
        libc::syscall(
            SYS_OPENAT2,
            libc::AT_FDCWD,
            b"\0".as_ptr() as *const libc::c_char,
            how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    } {
        -1 => matches!(unsafe { *libc::__errno_location() }, libc::ENOENT),

        fd => {
            // This shouldn't happen.
            // Close the file descriptor and conservatively assume that `how` isn't supported
            unsafe {
                libc::close(fd as _);
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_openat2() {
        let mut how = OpenHow::new(libc::O_RDONLY, 0);

        if has_openat2() {
            assert!(has_openat2_cached());
            assert!(has_openat2_cached());

            assert!(supports_open_how(&how));

            let fd = openat2(None, ".", &how).unwrap();
            unsafe {
                libc::close(fd);
            }

            assert_eq!(
                openat2(None, "./NOEXIST", &how).unwrap_err().raw_os_error(),
                Some(libc::ENOENT)
            );

            how.resolve |= ResolveFlags::BENEATH;
            assert!(supports_open_how(&how));
            assert_eq!(
                openat2(None, "/", &how).unwrap_err().raw_os_error(),
                Some(libc::EXDEV)
            );
        } else {
            assert!(!has_openat2_cached());
            assert!(!has_openat2_cached());

            assert!(!supports_open_how(&how));

            let eno = openat2(None, ".", &how)
                .unwrap_err()
                .raw_os_error()
                .unwrap();

            assert!(matches!(eno, libc::ENOSYS | libc::EPERM));
        }
    }

    #[test]
    fn test_openhow_truncate_flags_mode() {
        let mut how = OpenHow::new(0, 0);

        how.flags = (libc::O_WRONLY | libc::O_TRUNC | libc::O_SYNC | libc::O_CLOEXEC) as u64;
        how.mode = 0o666;
        how.truncate_flags_mode();
        assert_eq!(
            how.flags,
            (libc::O_WRONLY | libc::O_TRUNC | libc::O_SYNC | libc::O_CLOEXEC) as u64
        );
        assert_eq!(how.mode, 0);

        how.flags = (libc::O_PATH | libc::O_WRONLY | libc::O_CLOEXEC) as u64;
        how.mode = 0o666;
        how.truncate_flags_mode();
        assert_eq!(how.flags, (libc::O_PATH | libc::O_CLOEXEC) as u64);
        assert_eq!(how.mode, 0);

        // O_CREAT and O_TMPFILE actually preserve the `flags` argument
        how.flags = (libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC) as u64;
        how.mode = 0o666;
        how.truncate_flags_mode();
        assert_eq!(
            how.flags,
            (libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC) as u64
        );
        assert_eq!(how.mode, 0o666);

        how.flags = (libc::O_WRONLY | libc::O_TMPFILE | libc::O_CLOEXEC) as u64;
        how.mode = 0o666;
        assert_eq!(
            how.flags,
            (libc::O_WRONLY | libc::O_TMPFILE | libc::O_CLOEXEC) as u64
        );
        how.truncate_flags_mode();
        assert_eq!(how.mode, 0o666);
    }
}
