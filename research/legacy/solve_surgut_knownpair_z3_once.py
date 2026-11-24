from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

import sys, csv
from pathlib import Path
sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr
import z3
import recover_desktop_tree as rdt
SRC_ROOT=Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT=Path(_case_value('c2cb6ef3d173e2cf36a2'))
folder='Сургутнефтегаз'
rdt.RECOVER_FOLDER=folder; rdt.SRC=SRC_ROOT/folder; rdt.MAX_GAP=4

def rotl32(x,n): return z3.RotateLeft(x,n)
def salsa20_words_z3(state):
    x=state[:]
    for _ in range(10):
        x[4] ^= rotl32(x[0] + x[12], 7); x[8] ^= rotl32(x[4] + x[0], 9); x[12] ^= rotl32(x[8] + x[4], 13); x[0] ^= rotl32(x[12] + x[8], 18)
        x[9] ^= rotl32(x[5] + x[1], 7); x[13] ^= rotl32(x[9] + x[5], 9); x[1] ^= rotl32(x[13] + x[9], 13); x[5] ^= rotl32(x[1] + x[13], 18)
        x[14] ^= rotl32(x[10] + x[6], 7); x[2] ^= rotl32(x[14] + x[10], 9); x[6] ^= rotl32(x[2] + x[14], 13); x[10] ^= rotl32(x[6] + x[2], 18)
        x[3] ^= rotl32(x[15] + x[11], 7); x[7] ^= rotl32(x[3] + x[15], 9); x[11] ^= rotl32(x[7] + x[3], 13); x[15] ^= rotl32(x[11] + x[7], 18)
        x[1] ^= rotl32(x[0] + x[3], 7); x[2] ^= rotl32(x[1] + x[0], 9); x[3] ^= rotl32(x[2] + x[1], 13); x[0] ^= rotl32(x[3] + x[2], 18)
        x[6] ^= rotl32(x[5] + x[4], 7); x[7] ^= rotl32(x[6] + x[5], 9); x[4] ^= rotl32(x[7] + x[6], 13); x[5] ^= rotl32(x[4] + x[7], 18)
        x[11] ^= rotl32(x[10] + x[9], 7); x[8] ^= rotl32(x[11] + x[10], 9); x[9] ^= rotl32(x[8] + x[11], 13); x[10] ^= rotl32(x[9] + x[8], 18)
        x[12] ^= rotl32(x[15] + x[14], 7); x[13] ^= rotl32(x[12] + x[15], 9); x[14] ^= rotl32(x[13] + x[12], 13); x[15] ^= rotl32(x[14] + x[13], 18)
    return [x[i]+state[i] for i in range(16)]
def word_from_bytes(bs):
    out=z3.BitVecVal(0,32)
    for i,b in enumerate(bs):
        bv=z3.BitVecVal(b,8) if isinstance(b,int) else b
        out = out | (z3.ZeroExt(24,bv) << (8*i))
    return out

def out_for(item):
    rel=Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT/Path(str(rel)[:-len(rdt.EXT)])

def build_ks(files):
    ks={}; oracle=None; nk=None
    for cand in sorted(files,key=lambda f:f.coverage,reverse=True):
        nk=rdt.run_dump_ks(cand)
        if nk: oracle=cand; break
    for i,b in enumerate(nk): ks[i]=b
    for it in sorted(files,key=lambda f:f.coverage,reverse=True):
        more=rdt.run_dump_ks(it)
        if more:
            for off,val in enumerate(more): rdt.merge_ks(ks,off,val)
    rdt.learn_name_len_metadata(ks,files); rdt.learn_stable_metadata_profiles(ks,files)
    # only cheap known-pair <=2 to avoid long brute
    changed=True
    while changed:
        changed=False
        for it in files:
            if not out_for(it).exists(): continue
            fek=rdt.derive_fek_from_ks(ks,it) or rdt.recover_fek_from_known_pair(it,ks)
            if fek:
                old=len(ks); rdt.learn_fek(ks,it,fek)
                if len(ks)>old: changed=True
    return ks

groups,_,_=lr.scan_source(SRC_ROOT/folder,[rdt.EXT],rdt.SCAN_EXTS,False,1,rdt.MAX_SIZE_BYTES,workers=1)
files=list(groups.values())[0]
ks=build_ks(files)
print('initial_cov',rdt.contiguous(ks),'known',len(ks), flush=True)
# choose recovered item with max fei_len/body signal
cands=[]
for it in files:
    out=out_for(it)
    if not out.exists(): continue
    fei_len,_,body_end,fei_ct,_=lr.read_fei_ciphertext(Path(it.path))
    start=fei_len-64
    missing=[i for i in range(64) if start+i not in ks]
    if missing:
        cands.append((len(missing), -fei_len, -body_end, it, missing))
for _,_,_,it,missing in sorted(cands)[:5]:
    print('cand',it.fei_len,'missing',len(missing),'name',it.original_name.encode('unicode_escape').decode(), flush=True)
# best with largest fei_len / manageable missing?
it=sorted(cands, key=lambda x:(x[0], x[1], x[2]))[0][3]
fei_len,_,body_end,fei_ct,_=lr.read_fei_ciphertext(Path(it.path))
out=out_for(it)
start=fei_len-64
missing=[i for i in range(64) if start+i not in ks]
print('SOLVE',it.fei_len,'missing',len(missing),it.original_name.encode('unicode_escape').decode(), flush=True)
with Path(it.path).open('rb') as ef, out.open('rb') as pf:
    expected=bytes(a^b for a,b in zip(ef.read(64),pf.read(64)))
unknowns={pos:z3.BitVec(f'b{pos}',8) for pos in missing}
fek_bytes=[]
for i in range(64):
    off=start+i
    fek_bytes.append(unknowns[i] if off not in ks else fei_ct[off]^ks[off])
state=[word_from_bytes(fek_bytes[i*4:i*4+4]) for i in range(16)]
out_words=salsa20_words_z3(state)
solver=z3.Solver(); solver.set('timeout',600000)
for wi,word in enumerate(out_words):
    solver.add(word == z3.BitVecVal(int.from_bytes(expected[wi*4:wi*4+4],'little'),32))
print('checking...', flush=True)
st=solver.check(); print('status',st, flush=True)
if st==z3.sat:
    m=solver.model(); fek=bytearray(64)
    for i,b in enumerate(fek_bytes):
        fek[i]=m.eval(b).as_long() if not isinstance(b,int) else b
    print('verify',rdt.salsa20_block(bytes(fek))==expected, 'fek', bytes(fek).hex(), flush=True)
    learned=rdt.learn_fek(ks,it,bytes(fek).hex())
    print('learned',learned,'cov_after',rdt.contiguous(ks), flush=True)
