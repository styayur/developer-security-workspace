use glib::collections::PtrSlice;
use glib::prelude::*;
use glib::translate::{FromGlib, GlibPtrDefault, IntoGlib, TransparentPtrType};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct Payload {
    drops: Arc<AtomicUsize>,
    should_panic: bool,
}

#[repr(transparent)]
struct Owned(*mut Payload);

impl Clone for Owned {
    fn clone(&self) -> Self {
        // SAFETY: each live Owned uniquely owns a non-null Box allocation.
        let value = unsafe { &*self.0 };
        Self(Box::into_raw(Box::new(Payload {
            drops: value.drops.clone(),
            should_panic: value.should_panic,
        })))
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: representation is one uniquely owned Box pointer, moved once.
        let value = unsafe { Box::from_raw(self.0) };
        value.drops.fetch_add(1, Ordering::SeqCst);
        assert!(!value.should_panic, "synthetic destructor panic");
    }
}

impl GlibPtrDefault for Owned {
    type GlibType = *mut Payload;
}

// SAFETY: repr(transparent) has precisely the single GlibType pointer layout.
unsafe impl TransparentPtrType for Owned {}

pub fn verify() {
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
            Owned(Box::into_raw(Box::new(Payload {
                drops: drops.clone(),
                should_panic: index == 2,
            })))
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
    slice.push(Owned(Box::into_raw(Box::new(Payload {
        drops: counts[1].clone(),
        should_panic: false,
    }))));
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
        assert_eq!(
            unsafe { glib::LogLevel::from_glib(level.into_glib()) },
            level
        );
    }
    let panic = std::panic::catch_unwind(|| unsafe { glib::LogLevel::from_glib(0x8000_0000) });
    match panic {
        Err(payload) => assert_eq!(payload.downcast_ref::<&str>(), Some(&"Unknown log level")),
        Ok(_) => panic!("unknown log level must remain rejected"),
    }
}
