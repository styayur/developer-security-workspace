use glib::collections::PtrSlice;
use glib::prelude::*;
use glib::translate::{GlibPtrDefault, IntoGlib, TransparentPtrType};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Clone)]
struct Payload {
    drops: Arc<AtomicUsize>,
    should_panic: bool,
}

#[repr(transparent)]
#[derive(Clone)]
struct Owned(Box<Payload>);

impl Drop for Payload {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        assert!(!self.should_panic, "synthetic destructor panic");
    }
}

impl GlibPtrDefault for Owned {
    type GlibType = *mut Payload;
}

// SAFETY: repr(transparent) preserves Box<Payload>'s documented single-pointer
// layout for Sized Payload. Only uniquely owned, initialized global-allocator
// Boxes enter PtrSlice; its live slots are never null, and it moves each Owned
// exactly once before dropping it. Clone deep-copies the allocation using Box.
// https://doc.rust-lang.org/std/boxed/index.html#memory-layout
unsafe impl TransparentPtrType for Owned {}

pub fn verify() {
    // Safe operations exercise the guarded non-null GObject/GValue paths with
    // real initialized allocations and their original ownership/refcounts.
    let object = glib::Object::new::<glib::Object>();
    let weak_object = object.downgrade();
    let object_value = object.to_value();
    let object_value_copy = object_value.clone();
    assert_eq!(object_value_copy.get::<glib::Object>().unwrap(), object);
    let string_value = "initialized value".to_value();
    let string_value_copy = string_value.clone();
    assert_eq!(
        string_value_copy.get::<String>().unwrap(),
        "initialized value"
    );
    drop(object_value);
    drop(object_value_copy);
    assert!(weak_object.upgrade().is_some());
    drop(object);
    assert!(weak_object.upgrade().is_none());

    let objects = [
        glib::Object::new::<glib::Object>(),
        glib::Object::new::<glib::Object>(),
        glib::Object::new::<glib::Object>(),
    ];
    let weak = objects.each_ref().map(ObjectExt::downgrade);
    let mut objects: PtrSlice<glib::Object> = objects.into_iter().collect();
    objects.truncate(2);
    assert_eq!(objects.len(), 2);
    assert!(weak[0].upgrade().is_some());
    assert!(weak[1].upgrade().is_some());
    assert!(weak[2].upgrade().is_none());
    assert!(unsafe { (*objects.as_ptr().add(objects.len())).is_null() });
    objects.truncate(0);
    assert!(objects.is_empty());
    assert!(weak.iter().all(|value| value.upgrade().is_none()));
    assert!(unsafe { (*objects.as_ptr()).is_null() });
    let counts = [
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
    ];
    let mut slice: PtrSlice<Owned> = counts
        .iter()
        .enumerate()
        .map(|(index, drops)| {
            Owned(Box::new(Payload {
                drops: drops.clone(),
                should_panic: index == 2,
            }))
        })
        .collect();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slice.truncate(1)));
    assert!(panic.is_err());
    assert_eq!(slice.len(), 2);
    // SAFETY: PtrSlice reserves a readable terminator slot after its live items.
    assert!(unsafe { (*slice.as_ptr().add(slice.len())).is_null() });
    assert_eq!(counts[2].load(Ordering::SeqCst), 1);
    slice.truncate(1);
    assert_eq!(slice.len(), 1);
    assert!(unsafe { (*slice.as_ptr().add(slice.len())).is_null() });
    slice.push(Owned(Box::new(Payload {
        drops: counts[1].clone(),
        should_panic: false,
    })));
    assert_eq!(slice.len(), 2);
    drop(slice);
    assert_eq!(counts[0].load(Ordering::SeqCst), 1);
    assert_eq!(counts[1].load(Ordering::SeqCst), 2);
    assert_eq!(counts[2].load(Ordering::SeqCst), 1);

    for level in [
        glib::LogLevel::Error,
        glib::LogLevel::Critical,
        glib::LogLevel::Warning,
        glib::LogLevel::Message,
        glib::LogLevel::Info,
        glib::LogLevel::Debug,
    ] {
        assert_eq!(glib::LogLevel::try_from(level.into_glib()), Ok(level));
    }
    for invalid in [0, 1, 2, 3, 0x8000_0000] {
        assert_eq!(glib::LogLevel::try_from(invalid), Err(invalid));
    }
    // Preserve the old highest-priority recognized-bit behavior, including
    // foreign flag bits. Validation never logs the rejected numeric payload.
    assert_eq!(
        glib::LogLevel::try_from(0x8000_0000 | glib::ffi::G_LOG_LEVEL_WARNING),
        Ok(glib::LogLevel::Warning)
    );
    assert_eq!(
        glib::LogLevel::try_from(glib::ffi::G_LOG_LEVEL_ERROR | glib::ffi::G_LOG_LEVEL_WARNING),
        Ok(glib::LogLevel::Error)
    );
}
