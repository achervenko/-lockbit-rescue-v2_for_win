

# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

import hashlib
import json
import shutil
import sys
import zipfile
from pathlib import Path

BASE=Path(_case_value('e368ffff25523ab16333'))
sys.path.insert(0,_project_path(''))
import lockbit_rescue_v2 as lr

DEST=BASE/'outputs'/'gpu_04b4776408a3'
DEST.mkdir(parents=True,exist_ok=True)
(DEST/'data').mkdir(exist_ok=True)
state=json.loads((BASE/'tmp'/'brute-04b4776408a3'/'state.json').read_text(encoding='utf-8'))
files=[]
for folder in ['pdf-recovery-453','pdf-recovery-00106']:
    for p in (BASE/'tmp'/folder).rglob('*.xzg9VRelb'):
        x=lr.scan_file_worker((str(p.parent),p.name,['.xzg9VRelb'],set(),True))
        if x and x.kek_fingerprint==_case_value('840bb5a427ea610faa0c'): files.append(x)
manifest={'kek':_case_value('840bb5a427ea610faa0c'),'initial_keystream_hex':state['keystream_hex'],
          'files':[],'seed_tests':[],'chain':[]}
def add(item,label):
    relative='data/'+label+'.bin'
    dst=DEST/relative
    shutil.copy2(item.path,dst)
    row={'file':relative,'original_name':item.original_name,'fei_len':item.fei_len,
         'sha256':hashlib.sha256(dst.read_bytes()).hexdigest()}
    manifest['files'].append(row)
    return row
for name,key,kind in [
    (_case_value('7d817478e11a22b46218'),state['gap2_image']['fek'],'jpeg'),
    (_case_value('4a9d5ab896bd99ac4ea4'),state['gap3_pdf']['FEK'],'pdf')]:
    item=next(x for x in files if x.original_name==name)
    row=add(item,'seed_'+kind)
    manifest['seed_tests'].append({'file':row['file'],'fek':key,'kind':kind})
for length in range(116,126):
    choices=[x for x in files if x.fei_len==length and
             x.original_name.lower().endswith(('.sldprt','.sldasm','.slddrw'))
             and not x.original_name.startswith('~')]
    if not choices:
        choices=[x for x in files if x.fei_len==length and
                 x.original_name.lower().endswith(('.xlsb','.xlsx'))]
    if not choices: raise RuntimeError(f'No candidate for {length}')
    item=min(choices,key=lambda x:x.size)
    row=add(item,f'chain_{length}')
    kind='zip' if item.original_name.lower().endswith(('.xlsb','.xlsx')) else 'ole'
    manifest['chain'].append({**row,'kind':kind,
                             'magic_hex':'504b0304' if kind=='zip' else 'd0cf11e0a1b11ae1',
                             'final':False})
target=next(x for x in files if x.original_name==_case_value('a2be1c0676f3efd542bf'))
row=add(target,'target_pdf')
manifest['chain'].append({**row,'kind':'pdf','magic_hex':'255044462d312e','final':True})
(DEST/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
shutil.copy2(BASE/'tools'/'gpu_recovery_04b.py',DEST/'recover_gpu.py')
(DEST/'requirements.txt').write_text('numpy>=1.26\npyopencl>=2024.1\nPillow>=10\nolefile>=0.47\nPyMuPDF>=1.24\n',encoding='ascii')
install='''@echo off
cd /d "%~dp0"
py -3 -m venv .venv
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m pip install --upgrade pip
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto fail
.venv\Scripts\python.exe recover_gpu.py --selftest
if errorlevel 1 goto fail
echo SETUP AND GPU SELF-TEST PASSED. Run 2_RUN_GPU.cmd
pause
exit /b 0
:fail
echo ERROR. Copy the error text above.
pause
exit /b 1
'''
run='''@echo off
cd /d "%~dp0"
.venv\Scripts\python.exe -u recover_gpu.py %*
if errorlevel 1 echo ERROR OR INTERRUPTED. See the message above.
pause
'''
(DEST/'1_SETUP.cmd').write_text(install.replace('\n','\r\n'),encoding='ascii')
(DEST/'2_RUN_GPU.cmd').write_text(run.replace('\n','\r\n'),encoding='ascii')
readme=_case_value('fb9a1da00c8217d4228f')
(DEST/'README_RU.txt').write_text(readme,encoding='utf-8-sig')
print(DEST)
print([(x['fei_len'],x['original_name']) for x in manifest['chain']])
