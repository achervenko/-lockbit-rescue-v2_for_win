from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

import sys, json, tempfile, shutil
from pathlib import Path
sys.path.insert(0,_project_path(''))
import lockbit_rescue_v2 as lr, recover_desktop_tree as rdt
folder='Сургутнефтегаз'; rdt.RECOVER_FOLDER=folder; rdt.SRC=rdt.SRC_ROOT/folder; rdt.MAX_GAP=4; rdt.BRUTE_TIMEOUT_GAP3_PLUS=600
reports=rdt.REPORTS; reports.mkdir(parents=True,exist_ok=True)
groups,_,_=lr.scan_source(rdt.SRC,[rdt.EXT],rdt.SCAN_EXTS,False,1,rdt.MAX_SIZE_BYTES,workers=1)
for kek, files in groups.items():
    files=sorted(files,key=lambda f:(f.fei_len,f.original_name.lower()))
    ks={}; oracle=None; nk=None
    for cand in sorted(files,key=lambda f:f.coverage,reverse=True):
        nk=rdt.run_dump_ks(cand)
        if nk: oracle=cand; break
    for i,b in enumerate(nk): ks[i]=b
    for it in sorted(files,key=lambda f:f.coverage,reverse=True):
        if it.path==oracle.path: continue
        more=rdt.run_dump_ks(it)
        if more:
            for off,val in enumerate(more): rdt.merge_ks(ks,off,val)
    rdt.learn_name_len_metadata(ks,files); rdt.learn_stable_metadata_profiles(ks,files)
    print('start_cov',rdt.contiguous(ks), flush=True)
    changed=True; learned=set(); failed={}
    while changed:
        changed=False
        for it in files:
            cov=rdt.contiguous(ks)
            if it.path in learned or failed.get(it.path)==cov: continue
            if not rdt.output_path_for(it).exists(): continue
            ok,reason,n=rdt.learn_existing_item(it,oracle,ks,oracle.coverage)
            if ok:
                learned.add(it.path); changed=True
                if len(learned)%25==0 or n:
                    print('learned',len(learned),'cov',rdt.contiguous(ks),'last',it.fei_len,reason,n, flush=True)
            elif not reason.startswith('gap_'):
                failed[it.path]=cov
    cov=rdt.contiguous(ks)
    print('FINAL_COV',cov,'known',len(ks),'learned',len(learned),'failed',len(failed), flush=True)
    (reports/f'{folder}_ks_{kek}.json').write_text(json.dumps({str(k):v for k,v in ks.items()},ensure_ascii=False,indent=2),encoding='utf-8')
    # Try remaining with current ks. For gap 0 strict failures, write preview diagnostics.
    restored=0
    for it in sorted(files,key=lambda x:-Path(x.path).stat().st_size):
        if rdt.output_path_for(it).exists(): continue
        gap=max(0,it.fei_len-cov); ext=rdt.infer_ext(it.original_name)
        if gap>4: continue
        print('TRY_REMAIN',it.original_name.encode('unicode_escape').decode(),'ext',ext,'fei',it.fei_len,'gap',gap,'size',Path(it.path).stat().st_size, flush=True)
        ok,reason,n=rdt.recover_item(it,oracle,ks,oracle.coverage)
        print(' ->',ok,reason,n, flush=True)
        if ok: restored+=1; continue
        # If FEK is known, produce diagnostic temp head info using FEI/default params.
        fek=rdt.derive_fek_from_ks(ks,it)
        if fek:
            before,after,skipped,src=rdt.chunking_params_for(it,ks)
            with tempfile.TemporaryDirectory() as td:
                tmp=Path(td)/'dec'
                with rdt.helper_path(it.path,'diag') as hp:
                    dok=rdt.direct_decrypt_with_timeout(rdt.REPO/'direct-decrypt.exe',hp,tmp,fek,max(0,before-1),max(0,after-1),hex(skipped))
                if dok:
                    data=tmp.read_bytes()
                    print(' diag params',before,after,hex(skipped),src,'head',data[:16].hex(),'tail_has_eof',b'%%EOF' in data[-8192:],'valid',rdt.validate_recovered(tmp,ext), flush=True)
    print('RESTORED_IN_DIAG',restored, flush=True)
