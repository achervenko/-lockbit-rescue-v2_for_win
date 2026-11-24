"""Package code separately from the private local research archive."""
import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write_archive(destination, files):
    if destination.exists():
        raise FileExistsError(destination)
    hashes = {}
    with zipfile.ZipFile(destination, 'x', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name in sorted(set(files)):
            path = ROOT / name
            if not path.is_file():
                continue
            content = path.read_bytes()
            archive.writestr(name, content)
            hashes[name] = hashlib.sha256(content).hexdigest()
        archive.writestr('ARCHIVE_SHA256.json', json.dumps(hashes, indent=2) + '\n')
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise ValueError('Archive CRC check failed')
        for name, digest in hashes.items():
            if hashlib.sha256(archive.read(name)).hexdigest() != digest:
                raise ValueError(f'Archive SHA-256 mismatch: {name}')
    print(json.dumps({'archive': str(destination), 'files': len(hashes),
                      'bytes': destination.stat().st_size}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--label', required=True)
    parser.add_argument('--include-private', action='store_true')
    args = parser.parse_args()
    if any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in args.label):
        raise ValueError('Label must be a simple filename component')
    args.output.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                            cwd=ROOT, check=True, capture_output=True)
    names = result.stdout.decode('utf-8').split('\0')
    names = [n for n in names if n and not n.startswith('research/_local/')
             and not Path(n).suffix.lower() in {'.pdf', '.xzg9vrelb'}]
    write_archive(args.output / f'lockbit_research_CODE_{args.label}.zip', names)
    if args.include_private:
        local = [str(p.relative_to(ROOT)).replace('\\', '/')
                 for p in (ROOT/'research/_local').rglob('*') if p.is_file()]
        write_archive(args.output / f'lockbit_research_LOCAL_PRIVATE_{args.label}.zip', names + local)


if __name__ == '__main__':
    main()
