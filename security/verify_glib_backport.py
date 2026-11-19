import hashlib, json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
binding = json.loads((root / 'security/glib-provenance.json').read_text())
payload = root / 'vendor/glib'
assert {p.relative_to(payload).as_posix() for p in payload.rglob('*') if p.is_file()} == set(binding['payloadSha256']), 'payload inventory'
for name, expected in binding['payloadSha256'].items():
    assert hashlib.sha256((payload / name).read_bytes()).hexdigest() == expected, name
source = (payload / 'src/variant_iter.rs').read_text()
assert 'let mut p: *mut libc::c_char' in source and '                &mut p,' in source
assert binding['version'] == '0.18.5'
print('Verified GTK3-compatible GLib source backport:', binding['upstreamFix'])
