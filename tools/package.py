"""Build explicit distributables and reject private material in every archive."""

import hashlib
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = {'private', '.runtime', 'legacy', 'results', 'reports', 'vendor', '.venv', '.git', '__pycache__'}


def audit(names):
    for name in names:
        parts = Path(name).parts
        if any(part in FORBIDDEN for part in parts) or name.endswith(('.pem', '.key')):
            raise SystemExit(f'Forbidden distribution member: {name}')


def main():
    subprocess.run([sys.executable, '-m', 'build'], cwd=ROOT, check=True)
    from vps_quality_lab import __version__
    dist = ROOT / 'dist'
    skill_root = ROOT / 'skills'
    skill = skill_root / 'vps-quality-lab'
    target = dist / f'vps-quality-lab-skill-{__version__}.zip'
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(skill.rglob('*')):
            if path.is_file():
                archive.write(path, path.relative_to(skill_root))
    packages = sorted([dist / f'vps_quality_lab-{__version__}-py3-none-any.whl',
                       dist / f'vps_quality_lab-{__version__}.tar.gz', target])
    for path in packages:
        if path.suffix == '.gz':
            with tarfile.open(path) as archive:
                audit(archive.getnames())
        else:
            with zipfile.ZipFile(path) as archive:
                audit(archive.namelist())
    (dist / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in packages))
    print('Built and audited:', ', '.join(p.name for p in packages))


if __name__ == '__main__':
    main()
