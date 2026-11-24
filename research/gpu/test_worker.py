"""Short CPU checks only; actual OpenCL tests use recover_gpu.py --selftest."""
import importlib.util
import json
import struct
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("gpu_worker", Path(__file__).with_name("recover_gpu.py"))
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)

# Independent Salsa20/20 known-answer vector for a zero 256-bit key and nonce.
state = [0] * 16
state[0], state[5], state[10], state[15] = struct.unpack('<4I', b'expand 32-byte k')
expected = bytes.fromhex(
    '9a97f65b9b4c721b960a672145fca8d4'
    'e32e67f9111ea979ce9c4826806aeee6'
    '3de9c0da2bd7f91ebcb2639bf989c625'
    '1b29bf38d39a9bdce7c55f4b2ac12a39'
)
assert worker.block(state) == expected
assert state[8] == 0

identity = worker.task_id(b'{"task":"synthetic"}')
stages = [{'fei_len': 64}]
progress = {'task_id': identity, 'stage': 0, 'next_guess': 42,
            'keystream_hex': '00' * 63, 'results': []}
worker.check_resume(progress, identity, stages)
for patch in ({'task_id': 'other'}, {'next_guess': 257}, {'stage': -1}):
    try:
        worker.check_resume({**progress, **patch}, identity, stages)
    except ValueError:
        pass
    else:
        raise AssertionError('Invalid checkpoint accepted')
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    worker.atomic_json(root / 'progress.json', progress)
    assert json.loads((root / 'progress.json').read_text()) == progress
    assert not (root / 'progress.tmp').exists()
    assert worker.task_path(root, 'data/input.bin').is_relative_to(root)
    try:
        worker.task_path(root, '../outside.bin')
    except ValueError:
        pass
    else:
        raise AssertionError('Path traversal accepted')
print('CPU Salsa20 vector, checkpoint identity/range, atomic save and path containment PASS')
