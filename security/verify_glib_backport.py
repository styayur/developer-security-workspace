import sys
import hashlib, json, tomllib
from pathlib import Path
root = Path(__file__).resolve().parents[1]
binding = json.loads((root / 'security/glib-provenance.json').read_text())
payload = root / 'vendor/glib'
assert {p.relative_to(payload).as_posix() for p in payload.rglob('*') if p.is_file()} == set(binding['payloadSha256']), 'payload inventory'
for name, expected in binding['payloadSha256'].items():
    assert hashlib.sha256((payload / name).read_bytes()).hexdigest() == expected, name
if 'localHardeningPatchSha256' in binding:
    assert hashlib.sha256((root / 'security/glib-local-hardening.patch').read_bytes()).hexdigest() == binding['localHardeningPatchSha256'], 'local hardening patch'
for name, expected in binding.get('auxiliarySha256', {}).items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name
manifest = tomllib.loads((root / 'src-tauri/Cargo.toml').read_text())
assert (root / 'src-tauri' / manifest['patch']['crates-io']['glib']['path']).resolve() == payload.resolve(), 'application must use this payload'
lock = tomllib.loads((root / 'src-tauri/Cargo.lock').read_text())
glib = [p for p in lock['package'] if p['name'] == 'glib']
assert len(glib) == 1 and glib[0]['version'] == '0.18.5' and 'source' not in glib[0] and 'checksum' not in glib[0], 'root GLib lock identity'
test_manifest = tomllib.loads((root / 'security/glib-regression/Cargo.toml').read_text())
assert (root / 'security/glib-regression' / test_manifest['dependencies']['glib']['path']).resolve() == payload.resolve(), 'regression must compile the application payload'
source = (payload / 'src/variant_iter.rs').read_text()
assert 'let mut p: *mut libc::c_char' in source and '                &mut p,' in source
assert binding['version'] == '0.18.5'
sys.stdout.write('Verified GTK3-compatible GLib source backport: ' + binding['upstreamFix'] + '\n')
