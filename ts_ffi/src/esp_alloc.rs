//! Put the Rust heap in PSRAM on ESP-IDF.
//!
//! By default Rust allocates through `malloc`, and ESP-IDF's `malloc` serves
//! small requests from internal DRAM first. That is the same ~110 KB pool that
//! FreeRTOS objects and every thread stack must come from -- and stacks for any
//! thread that may write flash *have* to live there, because a task on a PSRAM
//! stack may not be the one that disables the flash cache.
//!
//! Measured on an ESP32-S3 with WiFi, mDNS, NTP and both web servers up: 112 KB
//! of internal DRAM free before the tokio runtime is built. Starting the
//! runtime then exhausted it, and the failure surfaced as
//! `pthread_mutex_init(...).unwrap()` panicking inside std -- ESP-IDF backs each
//! pthread mutex with a FreeRTOS semaphore allocated from internal DRAM. The
//! panic handler needs a mutex of its own, so it panicked again, and the
//! double panic reset the chip without printing "Rebooting...".
//!
//! The board has ~2 MB of PSRAM and nothing else was using it, so send Rust's
//! heap there and leave internal DRAM to what genuinely needs it. PSRAM is
//! slower than internal RAM, which does not matter at this workload.
//!
//! Safe with respect to the flash-cache restriction: while one core writes
//! flash, ESP-IDF stalls the other, so no Rust code can be touching the heap
//! at that moment regardless of where it lives.

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::ptr;

// From esp_heap_caps.h.
const MALLOC_CAP_8BIT: u32 = 1 << 2;
const MALLOC_CAP_SPIRAM: u32 = 1 << 10;

const PSRAM: u32 = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
/// Fallback: anything byte-addressable, i.e. internal DRAM once PSRAM is full.
const ANYWHERE: u32 = MALLOC_CAP_8BIT;

/// ESP-IDF's heap guarantees 4-byte alignment. Same constant std uses for this
/// target (library/std/src/sys/alloc/mod.rs, MIN_ALIGN).
const MIN_ALIGN: usize = 4;

unsafe extern "C" {
    fn heap_caps_malloc(size: usize, caps: u32) -> *mut c_void;
    fn heap_caps_aligned_alloc(alignment: usize, size: usize, caps: u32) -> *mut c_void;
    fn heap_caps_realloc(ptr: *mut c_void, size: usize, caps: u32) -> *mut c_void;
    fn heap_caps_free(ptr: *mut c_void);
}

unsafe fn alloc_with(layout: Layout, caps: u32) -> *mut u8 {
    // SAFETY: plain C allocator calls; the caller upholds GlobalAlloc's contract.
    unsafe {
        if layout.align() <= MIN_ALIGN {
            heap_caps_malloc(layout.size(), caps).cast()
        } else {
            heap_caps_aligned_alloc(layout.align(), layout.size(), caps).cast()
        }
    }
}

pub struct PsramFirst;

unsafe impl GlobalAlloc for PsramFirst {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded contract.
        unsafe {
            let p = alloc_with(layout, PSRAM);
            if !p.is_null() {
                return p;
            }
            alloc_with(layout, ANYWHERE)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // heap_caps_free handles blocks from either region, aligned or not.
        // SAFETY: ptr came from alloc/realloc above.
        unsafe { heap_caps_free(ptr.cast()) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded contract.
        unsafe {
            if layout.align() <= MIN_ALIGN {
                // heap_caps_realloc moves the block if it does not satisfy the
                // caps, and leaves the original untouched when it returns null,
                // so falling back is safe.
                let p = heap_caps_realloc(ptr.cast(), new_size, PSRAM);
                if !p.is_null() {
                    return p.cast();
                }
                return heap_caps_realloc(ptr.cast(), new_size, ANYWHERE).cast();
            }
            // Over-aligned: realloc does not preserve alignment, so move by hand.
            let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
            let new_ptr = self.alloc(new_layout);
            if !new_ptr.is_null() {
                ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
            new_ptr
        }
    }
}
