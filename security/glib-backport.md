# GTK3 GLib security backport

Tauri/wry's Linux GTK3 stack uses glib 0.18.5. Replacing it with glib 0.20
would introduce different Rust types/GTK ABI bindings and does not satisfy the
GTK3 dependency requirements. Windows does not use this GTK implementation.

The MIT-licensed crate in `vendor/glib` is the exact crates.io 0.18.5 archive
(checksum in `glib-provenance.json`) plus upstream gtk-rs-core commit
`b5a4071e439bef2b5eea76c3aa25e5ae84839e34`: declare the output pointer mutable
and pass `&mut p` to `g_variant_get_child`. Its public API/version are retained.
An empty Cargo workspace isolates upstream lint/dev tooling. Two additional
local hardenings are separately recorded in the inventory: an unknown log level
still panics but does not print foreign numeric bits, and `PtrSlice::truncate`
moves the owned value out, restores the NULL slot, then runs its destructor.
This keeps the live prefix and terminator valid if a destructor unwinds. The
container still owns and eventually frees its allocation. Public API, valid
value conversion and dependency requirements remain unchanged. MIT notices are
retained; these local changes are not attributed to the upstream iterator fix.

The lockfile points to the local path patch. `verify_glib_backport.py` verifies
all vendored bytes. The optimized Linux regression exercises forward, reverse,
mixed and indexed string-variant iteration, including empty and Unicode values.
CI records Linux and Windows reverse dependency trees and uses `--locked` for
the regression harness. The installed Tauri dependency is the same patched path.
The harness additionally verifies destructor counts, a throwing destructor,
post-unwind NULL termination, truncation/reuse and final destruction; ordinary
GObject truncation/weak-reference lifetime and valid/invalid log conversions are exercised too. The
foreign GLib allocator/FFI path is tested natively on Linux, not claimed as a
Miri result. Full CodeQL analysis remains enabled for the other findings.

The successor source attempt adds real release-mode null checks before
ObjectRef none/full/borrow and GValue copy/clear dereferences. These checks
reject null before memory access; they do not establish allocation liveness,
alignment, initialization, dynamic type or ownership. Those remain obligations
of the unsafe caller. Existing refcount and GValue type checks are retained.
Valid caller behavior and native allocation/refcount operations are unchanged.
The macro-derived boxed conversion finding is separately under investigation;
neither current findings nor scanner gates are waived.

Safe `LogLevel::try_from(u32)` validation is an additive API reviewed against
the peer maintenance source at Vextessera commit
`32b8a75f9f3c1c3544f4cd1e6515aeb86b59cc1d`. The old `FromGlib` implementation
delegates to the same accepted-bit priority and still panics with the constant
message on rejected flags. The harness exercises valid, invalid and combined
bits through the safe API; it does not claim to execute the old unsafe invalid
conversion. Its throwing-destructor fixture now uses a transparent Rust
`Box<Payload>`, safe derived cloning and `Payload::drop` instead of manually
dereferencing/reconstructing owned raw pointers. Sized Box single-pointer ABI
and ownership are documented at https://doc.rust-lang.org/std/boxed/index.html#memory-layout .
Payload allocations remain unique global-allocator Boxes; GLib still owns its
outer pointer-array allocation. The panic/count/NULL-terminator/reuse tests are
retained, with real initialized GObject/GValue clone/refcount paths added.
The exact local delta and its SHA-256 are in `glib-local-hardening.patch` and
`glib-provenance.json`, separate from the two-line upstream iterator fix.

RUSTSEC-2024-0429 / GHSA-wrw7-89jp-8q8g formally marks all glib <0.20 affected.
This is a verified source backport, not a claim that upstream published a fixed
GTK3 release. Do not dismiss the advisory, change the package version to evade
it, or add audit ignores. Any remaining version-based alert stays visible until
upstream metadata/dependencies can represent the fix.

References:
- https://github.com/advisories/GHSA-wrw7-89jp-8q8g
- https://github.com/gtk-rs/gtk-rs-core/pull/1343
