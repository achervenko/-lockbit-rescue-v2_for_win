"""Portable GPU recovery for the authorized 04b4776408a3 data set."""


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

from pathlib import Path
import argparse
import hashlib
import io
import json
import struct
import time
import traceback

ROOT = Path(__file__).resolve().parent
MASK = 0xffffffff
CHUNK = 0x20000
ROUNDS = [(4,8,12,0),(9,13,1,5),(14,2,6,10),(3,7,11,15),
          (1,2,3,0),(6,7,4,5),(11,8,9,10),(12,13,14,15)]


def block(state):
    x = list(state)
    def rol(v,n):
        v &= MASK
        return ((v << n) | (v >> (32-n))) & MASK
    for _ in range(10):
        for a,b,c,d in ROUNDS:
            x[a] ^= rol(x[d]+x[c],7)
            x[b] ^= rol(x[a]+x[d],9)
            x[c] ^= rol(x[b]+x[a],13)
            x[d] ^= rol(x[c]+x[b],18)
    return struct.pack('<16I', *((x[i]+state[i]) & MASK for i in range(16)))


def footer(path):
    with path.open('rb') as f:
        f.seek(-134,2)
        tail = f.read(134)
        n = int.from_bytes(tail[:2],'little')
        f.seek(-134-n,2)
        fei = f.read(n)
    return fei, path.stat().st_size -134-n


def atomic_json(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    tmp.replace(path)


def key_for(path, ks):
    fei,_ = footer(path)
    start = len(fei)-64
    return bytes(fei[i]^ks[i] for i in range(start,len(fei)))


def decrypt(path, key, ks):
    import numpy as np
    fei,size = footer(path)
    meta_start = len(fei)-82
    meta = bytes(fei[i]^ks[i] for i in range(meta_start,meta_start+18))
    name_len,skip,before,after = struct.unpack('<HQII',meta)
    if name_len != meta_start or skip < CHUNK or before >4096 or after >4096:
        raise ValueError('Invalid per-file encryption parameters')
    state = list(struct.unpack('<16I',key))
    out = bytearray(path.read_bytes()[:size])
    pos = 0
    count = before+1
    while pos < size:
        end = min(size,pos+count*CHUNK)
        stream = bytearray()
        for _ in range((end-pos+63)//64):
            stream.extend(block(state))
            state[8] = (state[8]+1)&MASK
            if state[8] == 0:
                state[9] = (state[9]+1)&MASK
        region = np.frombuffer(out,dtype=np.uint8,count=end-pos,offset=pos)
        region ^= np.frombuffer(stream,dtype=np.uint8,count=end-pos)
        # LockBit skip is measured from the start of its last processed chunk.
        pos = end + skip-CHUNK
        count = after+1
    return bytes(out)


def validate(data, kind, render=False):
    if kind == 'zip':
        import zipfile
        with zipfile.ZipFile(io.BytesIO(data)) as doc:
            bad=doc.testzip()
            if bad or '[Content_Types].xml' not in doc.namelist():
                raise ValueError(f'Invalid Office ZIP: {bad}')
            return {'kind':'zip','entries':len(doc.namelist())}
    if kind == 'ole':
        import olefile
        if not data.startswith(bytes.fromhex('d0cf11e0a1b11ae1')):
            raise ValueError('OLE header mismatch')
        with olefile.OleFileIO(io.BytesIO(data),raise_defects=olefile.DEFECT_INCORRECT) as doc:
            streams=doc.listdir(streams=True,storages=False)
            if not streams:
                raise ValueError('Empty OLE directory')
            for name in streams:
                s=doc.openstream(name)
                while s.read(1024*1024):
                    pass
            return {'kind':'ole','streams':len(streams)}
    if kind == 'jpeg':
        from PIL import Image
        with Image.open(io.BytesIO(data)) as im:
            im.load()
            return {'kind':'jpeg','size':list(im.size)}
    if kind == 'pdf':
        import pymupdf
        if not data.startswith(b'%PDF-') or b'%%EOF' not in data[-4096:]:
            raise ValueError('PDF header or EOF missing')
        with pymupdf.open(stream=data,filetype='pdf') as doc:
            if doc.is_repaired or doc.page_count == 0:
                raise ValueError('PDF requires repair or has no pages')
            for page in doc:
                page.get_text()
                if render:
                    page.get_pixmap(matrix=pymupdf.Matrix(.5,.5))
            return {'kind':'pdf','pages':doc.page_count}
    raise ValueError(kind)


def kernel_source():
    qr='\n'.join(
        f'x{a} ^= rotate(x{d}+x{c},7U); x{b} ^= rotate(x{a}+x{d},9U); '
        f'x{c} ^= rotate(x{b}+x{a},13U); x{d} ^= rotate(x{c}+x{b},18U);'
        for a,b,c,d in ROUNDS)
    decl='\n'.join(f'uint x{i}=s[{i}];' for i in range(16))
    sums='\n'.join(f's[{i}]+=x{i};' for i in range(16))
    return '''
    __kernel void search(__global const uint *base,
      __global const uchar *fei, __global const uchar *ks,
      uint cov, uint flen, __global const uchar *cipher,
      __global const uchar *magic, uint magic_len,
      ulong start, ulong count, __global uint *hits,
      __global ulong *answers) {
        ulong gid=(ulong)get_global_id(0);
        if(gid>=count) return;
        ulong guess=start+gid;
        uint s[16];
        for(uint i=0;i<16;i++) s[i]=base[i];
        for(uint i=cov;i<flen;i++) {
          uint j=i-(flen-64); uint shift=(j%4)*8;
          uint byte=(uint)fei[i] ^ ((guess >> ((i-cov)*8)) & 255UL);
          s[j/4]=(s[j/4] & ~(255U<<shift)) | (byte<<shift);
        }
    '''+decl+'''
        for(uint r=0;r<10;r++) {
    '''+qr+''' }
    '''+sums+'''
        for(uint i=0;i<magic_len;i++) {
          uchar p=cipher[i] ^ (uchar)(s[i/4]>>((i%4)*8));
          if(p != magic[i]) return;
        }
        uint slot=atomic_inc(hits);
        if(slot<64) answers[slot]=guess;
    }
    '''


class GPU:
    def __init__(self, device_index=0):
        import numpy as np
        import pyopencl as cl
        self.np,self.cl=np,cl
        devices=[d for p in cl.get_platforms() for d in p.get_devices()
                 if d.type & cl.device_type.GPU]
        if not devices:
            raise RuntimeError('No OpenCL GPU. Install the graphics driver, then reboot.')
        for i,d in enumerate(devices):
            print(f'GPU {i}: {d.name}',flush=True)
        self.device=devices[device_index]
        self.ctx=cl.Context([self.device])
        self.queue=cl.CommandQueue(self.ctx)
        self.program=cl.Program(self.ctx,kernel_source()).build()
        self.kernel=cl.Kernel(self.program,'search')
        self.kernel.set_scalar_arg_dtypes([None,None,None,np.uint32,np.uint32,
            None,None,np.uint32,np.uint64,np.uint64,None,None])

    def prepare(self, fei, ks, cipher, magic):
        cl,np=self.cl,self.np
        start=len(fei)-64
        key=bytes(fei[i]^(ks[i] if i<len(ks) else 0) for i in range(start,len(fei)))
        state=np.frombuffer(key,dtype='<u4').copy()
        def buf(data):
            return cl.Buffer(self.ctx,cl.mem_flags.READ_ONLY|cl.mem_flags.COPY_HOST_PTR,
                             hostbuf=data)
        self.args=[buf(state),buf(fei),buf(bytes(ks)),np.uint32(len(ks)),
                   np.uint32(len(fei)),buf(cipher),buf(magic),np.uint32(len(magic))]
        self.hits=cl.Buffer(self.ctx,cl.mem_flags.READ_WRITE,4)
        self.answers=cl.Buffer(self.ctx,cl.mem_flags.READ_WRITE,64*8)

    def search(self,start,count):
        cl,np=self.cl,self.np
        hits=np.zeros(1,dtype=np.uint32)
        cl.enqueue_copy(self.queue,self.hits,hits)
        global_size=((count+127)//128)*128
        self.kernel(self.queue,(global_size,),(128,),*self.args,
                    np.uint64(start),np.uint64(count),self.hits,self.answers)
        cl.enqueue_copy(self.queue,hits,self.hits).wait()
        if hits[0]>64:
            raise RuntimeError('Too many hits; checkpoint retained. Use a stronger header.')
        if not hits[0]: return []
        out=np.empty(64,dtype=np.uint64)
        cl.enqueue_copy(self.queue,out,self.answers).wait()
        return sorted(int(v) for v in out[:hits[0]])

    def selftest(self):
        # Known-answer tests include all 5 unknown bytes and the exact 2^40 boundary.
        for missing,guess in [(2,0xd34b),(3,0x585e48),(5,0xe3a4821907),(5,(1<<40)-1)]:
            cov=111
            flen=cov+missing
            ks=bytes((i*73+19)&255 for i in range(cov))+guess.to_bytes(missing,'little')
            fei=bytes((i*31+7)&255 for i in range(flen))
            key=bytes(fei[i]^ks[i] for i in range(flen-64,flen))
            magic=bytes.fromhex('d0cf11e0a1b11ae1')
            stream=block(struct.unpack('<16I',key))
            cipher=bytes(a^b for a,b in zip(magic,stream))
            self.prepare(fei,ks[:cov],cipher,magic)
            lo=max(0,guess-100)
            count=min(256,(1<<(8*missing))-lo)
            if self.search(lo,count)!=[guess]:
                raise RuntimeError('GPU self-test failed; search NOT started.')
        print('GPU Salsa20 self-test: PASS (2/3/5-byte search and boundary)',flush=True)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--device',type=int,default=0)
    parser.add_argument('--batch-power',type=int,default=24)
    parser.add_argument('--selftest',action='store_true')
    parser.add_argument('--validate-seed',action='store_true')
    args=parser.parse_args()
    manifest=json.loads((ROOT/'manifest.json').read_text(encoding='utf-8'))
    for item in manifest['files']:
        p=ROOT/item['file']
        if hashlib.sha256(p.read_bytes()).hexdigest()!=item['sha256']:
            raise ValueError(f'Package file checksum failed: {p.name}')
    for seed in manifest['seed_tests']:
        ks=bytes.fromhex(manifest['initial_keystream_hex'])
        data=decrypt(ROOT/seed['file'],bytes.fromhex(seed['fek']),ks)
        info=validate(data,seed['kind'],render=True)
        print('Seed validated:',seed['file'],info,flush=True)
    if args.validate_seed:
        return
    gpu=GPU(args.device)
    gpu.selftest()
    if args.selftest:
        return
    if not 16<=args.batch_power<=28:
        raise ValueError('batch-power must be 16..28')
    state_path=ROOT/'progress.json'
    if state_path.exists():
        state=json.loads(state_path.read_text(encoding='utf-8'))
    else:
        state={'keystream_hex':manifest['initial_keystream_hex'],
               'stage':0,'next_guess':0,'results':[]}
    output=ROOT/'recovered'
    output.mkdir(exist_ok=True)
    stages=manifest['chain']
    while state['stage']<len(stages):
        item=stages[state['stage']]
        path=ROOT/item['file']
        ks=bytearray.fromhex(state['keystream_hex'])
        fei,_=footer(path)
        missing=len(fei)-len(ks)
        if missing>5:
            raise ValueError('Unexpected gap >5; refusing excessive search')
        if missing>0:
            with path.open('rb') as f: cipher=f.read(16)
            gpu.prepare(fei,ks,cipher,bytes.fromhex(item['magic_hex']))
            total=1<<(8*missing)
            pos=int(state['next_guess'])
            started=time.monotonic()
            start_pos=pos
            print(f'Stage {state["stage"]+1}/{len(stages)}: {item["original_name"]}; '
                  f'unknown={missing} bytes; resume={pos:,}/{total:,}',flush=True)
            found=None
            while pos<total:
                count=min(1<<args.batch_power,total-pos)
                guesses=gpu.search(pos,count)
                for guess in guesses:
                    candidate=ks+guess.to_bytes(missing,'little')
                    key=key_for(path,candidate)
                    data=decrypt(path,key,candidate)
                    try:
                        info=validate(data,item['kind'],render=item['final'])
                    except Exception as e:
                        print('Rejected candidate',hex(guess),str(e),flush=True)
                        continue
                    found=(candidate,key,data,info)
                    break
                if found: break
                pos+=count
                state['next_guess']=pos
                atomic_json(state_path,state)
                elapsed=time.monotonic()-started
                speed=(pos-start_pos)/max(elapsed,.001)
                print(f'{100*pos/total:.4f}% | {speed/1e6:.2f} M/s | '
                      f'ETA {(total-pos)/max(speed,1)/3600:.2f} h | checked {pos:,}',flush=True)
            if found is None:
                raise RuntimeError('Entire range exhausted. State saved; do not treat as success.')
            ks,key,data,info=found
        else:
            key=key_for(path,ks)
            data=decrypt(path,key,ks)
            info=validate(data,item['kind'],render=item['final'])
        result_path=output/item['original_name']
        result_path.write_bytes(data)
        result={'file':item['original_name'],'fek':key.hex(),'validation':info,
                'sha256':hashlib.sha256(data).hexdigest()}
        state['results'].append(result)
        state['keystream_hex']=bytes(ks).hex()
        state['stage']+=1
        state['next_guess']=0
        atomic_json(state_path,state)
        print('RECOVERED:',result_path,info,'coverage=',len(ks),flush=True)
    print('DONE. Target PDF:',output/_case_value('a2be1c0676f3efd542bf'),flush=True)


if __name__=='__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nStopped. Completed batches saved in progress.json. Run again to resume.')
        raise SystemExit(130)
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
