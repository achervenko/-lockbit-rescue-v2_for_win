

# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

import sys,json,struct,subprocess,zlib,hashlib,shutil,zipfile,io,time
from pathlib import Path
BASE=Path(_case_value('e368ffff25523ab16333'))
sys.path[:0]=[str(BASE/'tools'),_project_path(''),str(BASE/'tmp/gpu_package_validation_deps')]
import gpu_recovery_04b as g
import lockbit_rescue_v2 as lr
ROOT=BASE/'tmp/pdf-recovery-453'
DEST=Path(_case_value('0f75799e6764f107ddbc'))
RUN=BASE/'tmp/brute-04b4776408a3'
files=[]
for folder in [ROOT,BASE/'tmp/pdf-recovery-00106']:
 for p in folder.rglob('*.xzg9VRelb'):
  x=lr.scan_file_worker((str(p.parent),p.name,['.xzg9VRelb'],set(),True))
  if x and x.kek_fingerprint==_case_value('840bb5a427ea610faa0c'):files.append(x)
s=json.loads((RUN/'state.json').read_text(encoding='utf-8'))
ks=bytearray.fromhex(s['keystream_hex']+_case_value('61e7b8aaa60b94ce057a'))
cached=RUN/'expanded_ks.json'
if cached.exists():ks=bytearray.fromhex(json.loads(cached.read_text())['keystream_hex'])
DEST.mkdir(exist_ok=True)

def dec(x,known):
 p=Path(x.path); key=g.key_for(p,known); fei,_=g.footer(p); off=len(fei)-82
 meta=bytes(fei[i]^known[i] for i in range(off,off+18))
 name,skip,before,after=struct.unpack('<HQII',meta)
 if name!=off or skip<0x20000 or before>4096 or after>4096:raise ValueError('Bad metadata')
 out=RUN/'decoded_candidate.bin'
 subprocess.run([str(BASE/'tools/direct_04b.exe'),str(p),str(out),key.hex(),str(before),str(after),hex(skip-0x20000)],check=True,capture_output=True)
 return out.read_bytes()

def sw_check(b,require_first=False):
 if b.startswith(bytes.fromhex('d0cf11e0a1b11ae1')):return g.validate(b,'ole')
 if b[4:8]!=b'\0\0\0\4':raise ValueError('Not native SW or OLE')
 marker=bytes.fromhex(_case_value('a2eab93d37a3a5d9071a'));pos=0;count=0;first=0;catalog=0
 while True:
  pos=b.find(marker,pos)
  if pos<0:break
  off=pos;pos+=6
  if off+26>len(b):continue
  typ,crc,c,u,p=struct.unpack_from('<5I',b,off+6);start=off+26+p
  if p>4096 or c==0 or u>500_000_000 or start+c>len(b):catalog+=1;continue
  try:
   obj=zlib.decompressobj(-15);data=obj.decompress(b[start:start+c],u+1)
  except zlib.error:catalog+=1;continue
  if not obj.eof:catalog+=1;continue
  if len(data)!=u or zlib.crc32(data)!=crc:raise ValueError(f'SW CRC/length mismatch at {off:x}')
  count+=1
  if off<0x80000:first+=1
 if count==0 or (require_first and first==0):raise ValueError('No verified SW blocks in encrypted prefix')
 return {'kind':'SolidWorks native','CRC_blocks':count,'prefix_CRC_blocks':first,'other_markers':catalog}

def validate(b,name):
 ext=Path(name).suffix.lower()
 if ext in ['.sldprt','.sldasm','.slddrw']:
  return sw_check(b,True)
 if ext in ['.xlsb','.xlsx']:return g.validate(b,'zip')
 if ext=='.pdf':return g.validate(b,'pdf',render=True)
 if ext in ['.jpg','.jpeg']:return g.validate(b,'jpeg')
 if ext=='.dxf':
  if not (b.lstrip().startswith(b'0') and b'SECTION' in b[:2000] and b'EOF' in b[-2000:]):raise ValueError('DXF header/end invalid')
  return {'kind':'DXF','check':'header and EOF'}
 if ext=='.dwg':
  if not b.startswith(b'AC10'):raise ValueError('DWG header invalid')
  return {'kind':'DWG','check':'header only; open in CAD to verify'}
 return {'kind':ext,'check':'not supported'}

rows=[];completed=set()
def save_available():
 for x in files:
  p=Path(x.path)
  if not p.is_relative_to(ROOT) or x.path in completed or x.fei_len>len(ks):continue
  data=dec(x,ks);rel=p.relative_to(ROOT);out=DEST.joinpath(*rel.parts);out=out.with_name(x.original_name);out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(data)
  try: check=validate(data,x.original_name);status='VERIFIED'
  except Exception as e:check={'error':str(e)};status='DECRYPTED_NEEDS_REVIEW'
  rows.append({'file':str(out.relative_to(DEST)),'status':status,'check':check,'sha256':hashlib.sha256(data).hexdigest()});completed.add(x.path)
  print('SAVED',x.original_name,status,flush=True)
 (DEST/'RECOVERY_REPORT.json').write_text(json.dumps({'coverage':len(ks),'results':rows},ensure_ascii=False,indent=2),encoding='utf-8')

save_available()
while len(ks)<max(x.fei_len for x in files if Path(x.path).is_relative_to(ROOT)):
 choices=[x for x in files if len(ks)<x.fei_len<=len(ks)+3 and not x.original_name.startswith('~') and Path(x.original_name).suffix.lower() in ['.sldprt','.sldasm','.slddrw','.xlsb','.xlsx']]
 choices.sort(key=lambda x:(x.fei_len,x.size))
 found=False
 for x in choices:
  fei,_=g.footer(Path(x.path));gap=len(fei)-len(ks);cipher=Path(x.path).read_bytes()[:64];ext=Path(x.original_name).suffix.lower()
  patterns=[]
  if ext in ['.xlsb','.xlsx']:patterns=[(b'PK\3\4',b'\xff'*4)]
  else:patterns=[(b'\0'*4+b'\0\0\0\4',b'\0'*4+b'\xff'*4),(bytes.fromhex('d0cf11e0a1b11ae1'),b'\xff'*8)]
  for magic,mask in patterns:
   vector=struct.pack('<3I',len(fei),len(ks),len(magic))+fei+bytes(ks)+cipher.ljust(64,b'\0')+magic.ljust(64,b'\0')+mask.ljust(64,b'\0')
   vec=RUN/'search_vector.bin';vec.write_bytes(vector)
   print('SEARCH',len(ks),'->',x.fei_len,x.original_name,flush=True)
   res=subprocess.run([str(BASE/'tools/search_tail_04b.exe'),str(vec)],capture_output=True,text=True,check=True)
   for line in res.stdout.splitlines():
    guess=int(line,16);candidate=ks+guess.to_bytes(gap,'little')
    try:
     b=dec(x,candidate)
     check=g.validate(b,'zip') if ext in ['.xlsb','.xlsx'] else sw_check(b,True)
    except Exception:continue
    ks=candidate;cached.write_text(json.dumps({'keystream_hex':ks.hex(),'coverage':len(ks)}),encoding='utf-8');found=True;print('EXTENDED',len(ks),check,flush=True);break
   if found:break
  if found:break
 if not found:break
 save_available()
remaining=[{'name':x.original_name,'fei_len':x.fei_len,'missing':x.fei_len-len(ks)} for x in files if Path(x.path).is_relative_to(ROOT) and x.path not in completed]
(DEST/'RECOVERY_REPORT.json').write_text(json.dumps({'coverage':len(ks),'recovered':len(rows),'remaining':remaining,'results':rows},ensure_ascii=False,indent=2),encoding='utf-8')
print('FINAL',len(rows),'remaining',remaining,'DEST',str(DEST),flush=True)
