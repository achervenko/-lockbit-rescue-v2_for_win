from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

import sys,json,tempfile,shutil
from pathlib import Path
sys.path.insert(0,_project_path(''))
import lockbit_rescue_v2 as lr, recover_desktop_tree as rdt
folder='Сургутнефтегаз'; rdt.RECOVER_FOLDER=folder; rdt.SRC=rdt.SRC_ROOT/folder
kek=_case_value('3fdeba9d33ae472f3f02')
ks_path=rdt.REPORTS/f'{folder}_ks_{kek}.json'
ks={int(k):v for k,v in json.loads(ks_path.read_text(encoding='utf-8')).items()}
print('loaded_cov',rdt.contiguous(ks),'known',len(ks), flush=True)
groups,_,_=lr.scan_source(rdt.SRC,[rdt.EXT],rdt.SCAN_EXTS,False,1,rdt.MAX_SIZE_BYTES,workers=1)
files=list(groups.values())[0]
restored=[]
# target gap0 docs by size
for it in sorted(files,key=lambda x:-Path(x.path).stat().st_size):
    if rdt.output_path_for(it).exists(): continue
    if max(0,it.fei_len-rdt.contiguous(ks))!=0: continue
    ext=rdt.infer_ext(it.original_name)
    if ext not in {'pdf','xlsx','xlsm','docx','sldprt','sth_a'}: continue
    fek=rdt.derive_fek_from_ks(ks,it)
    if not fek: continue
    print('SWEEP',it.original_name.encode('unicode_escape').decode(),'ext',ext,'size',Path(it.path).stat().st_size/1024/1024, flush=True)
    best=[]; done=False
    skip_vals=[0x20000,0x40000,0x80000,0x100000,0x200000,0x520000,0x800000,0x1000000,0x2000000]
    # Direct binary appears to decrypt N+1 chunks in some cases; try both compensated and raw ranges.
    for before in range(0,9):
        for after in range(0,17):
            for skipped in skip_vals:
                with tempfile.TemporaryDirectory() as td:
                    tmp=Path(td)/'dec'
                    with rdt.helper_path(it.path,'swp') as hp:
                        ok=rdt.direct_decrypt_with_timeout(rdt.REPO/'direct-decrypt.exe',hp,tmp,fek,before,after,hex(skipped))
                    if not ok: continue
                    data=tmp.read_bytes(); score=0; flags=[]
                    if ext=='pdf':
                        if data.startswith(b'%PDF-'): score+=10; flags.append('head')
                        if b'%%EOF' in data[-65536:]: score+=20; flags.append('eof')
                        if b'startxref' in data[-262144:] or b'xref' in data[:1048576]: score+=5; flags.append('xref')
                    elif ext in {'docx','xlsx','xlsm'}:
                        if data.startswith(b'PK\x03\x04'): score+=10; flags.append('ziphead')
                    elif ext=='sldprt':
                        if data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1') or data.startswith(b'PK\x03\x04'): score+=10; flags.append('container')
                    else:
                        sample=data[:min(len(data),65536)]
                        pr=sum(1 for b in sample if b in b'\r\n\t' or 32<=b<127)/max(1,len(sample))
                        if pr>0.9: score+=10; flags.append(f'print{pr:.2f}')
                    valid=rdt.validate_recovered(tmp,ext)
                    if valid: score+=100; flags.append('VALID')
                    if score:
                        best.append((score,before,after,skipped,flags))
                    if valid:
                        dst=rdt.output_path_for(it); dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(tmp,dst)
                        rdt.learn_fek(ks,it,fek)
                        restored.append(str(dst)); print(' RESTORED',before,after,hex(skipped),flags, flush=True)
                        done=True; break
                if done: break
            if done: break
        if done: break
    if not done:
        for row in sorted(best, reverse=True)[:8]:
            print(' cand',row[0],row[1],row[2],hex(row[3]),row[4], flush=True)
print('RESTORED',len(restored), flush=True)
for p in restored: print(p.encode('unicode_escape').decode(), flush=True)
