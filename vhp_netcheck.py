
# VHP NetCheck v2.0 | Created by VHP_Shivam Rathod
import argparse,csv,datetime as dt,ipaddress,json,os,re,shutil,subprocess,sys,time,xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse
C='\033[96m';G='\033[92m';Y='\033[93m';R='\033[91m';X='\033[0m';B='\033[1m'
def p(s,c): return c+str(s)+X
def banner():
 os.system('clear' if os.name!='nt' else 'cls')
 print(p('╔══════════════════════════════════════════════════════════╗',C))
 print(p('║              VHP NETCHECK  v2.0                          ║',C+B))
 print(p('║       DEEP EXPOSURE & CONFIGURATION ASSESSMENT           ║',C))
 print(p('║       Created by: VHP_Shivam Rathod                     ║',C))
 print(p('╚══════════════════════════════════════════════════════════╝',C))
 print(' Authorized assets only | No exploitation, brute force or DoS')
def run(c,t=7200):
 try:
  x=subprocess.run(c,text=True,capture_output=True,timeout=t);return x.returncode,x.stdout,x.stderr
 except subprocess.TimeoutExpired:return 124,'','Timed out'
def target(s):
 s=s.strip()
 if '://' in s:s=urlparse(s).hostname or ''
 try:
  n=ipaddress.ip_network(s,strict=False)
  if n.num_addresses>256:raise ValueError('Max 256 addresses per run; split authorized scope.')
  return str(n),n.num_addresses
 except ValueError as e:
  if 'Max 256' in str(e):raise
 if re.fullmatch(r'[A-Za-z0-9.-]+',s) and '.' in s:return s,1
 raise ValueError('Enter valid IP, CIDR, hostname or URL.')
def scan(t,profile,out):
 if not shutil.which('nmap'):raise RuntimeError('Install Nmap: sudo apt install nmap')
 c=['nmap','-n','-T3','--reason','--open','-oX',str(out/'nmap.xml')]
 c+=['-sS'] if hasattr(os,'geteuid') and os.geteuid()==0 else ['-sT']
 if profile=='quick':c+=['-F','-sV','--version-light']
 elif profile=='deep':c+=['-p-','-sV','--version-all','--script','banner,http-title,http-headers,ssl-cert,ssl-enum-ciphers,ssh2-enum-algos,smb-protocols']
 else:c+=['--top-ports','1000','-sV','--version-light','--script','banner,http-title,http-headers,ssl-cert,ssh2-enum-algos,smb-protocols']
 c += [t];print(p('\n[1/3] Nmap scan running…',C));print(' '.join(c))
 rc,so,se=run(c);(out/'nmap-output.txt').write_text(so+'\n'+se,encoding='utf-8')
 if rc not in (0,1):raise RuntimeError(se or 'Nmap failed')
def parse(path):
 hs=[];fs=[]
 if not path.exists():return hs,fs
 root=ET.parse(path).getroot()
 for h in root.findall('host'):
  a=h.find('address');ip=a.get('addr','?') if a is not None else '?'
  st=h.find('status');state=st.get('state','?') if st is not None else '?';ports=[]
  for po in h.findall('./ports/port'):
   se=po.find('state')
   if se is None or se.get('state')!='open':continue
   sv=po.find('service');name=sv.get('name','unknown') if sv is not None else 'unknown'
   product=sv.get('product','') if sv is not None else '';version=sv.get('version','') if sv is not None else ''
   ports.append({'port':po.get('portid'),'protocol':po.get('protocol'),'service':name})
   fs.append({'severity':'INFO','title':f"Open {po.get('protocol')} port {po.get('portid')} ({name})",'asset':ip,'status':'Exposure only — not confirmed vulnerability','evidence':f'Open; service={name}; product={product}; version={version}','impact':'Reachability increases attack surface but does not prove unauthorized access.','remediation':'Confirm business need and restrict access to trusted sources.'})
   for sc in po.findall('script'):
    if sc.get('id') in {'http-headers','ssl-cert','ssl-enum-ciphers','ssh2-enum-algos','smb-protocols','banner','http-title'} and sc.get('output'):
     fs.append({'severity':'INFO','title':'Configuration evidence: '+sc.get('id'),'asset':ip+':'+po.get('portid'),'status':'Manual validation required','evidence':sc.get('output','')[:2500],'impact':'Evidence needs manual interpretation.','remediation':'Compare with vendor security baseline.'})
  hs.append({'ip':ip,'state':state,'ports':ports})
 return hs,fs
def nuclei(t,out):
 if not shutil.which('nuclei'):print(p('[2/3] Nuclei absent; optional checks skipped.',Y));return []
 f=out/'nuclei.jsonl';print(p('[2/3] Rate-limited configuration templates…',C))
 _,_,err=run(['nuclei','-u',t,'-tags','misconfig,exposure,headers,ssl','-severity','info,low,medium,high,critical','-rl','3','-c','5','-retries','1','-timeout','5','-jsonl','-o',str(f),'-silent'],1800)
 if err:(out/'nuclei-stderr.txt').write_text(err,encoding='utf-8')
 fs=[]
 if f.exists():
  for line in f.read_text(errors='ignore').splitlines():
   try:
    x=json.loads(line);i=x.get('info',{})
    fs.append({'severity':str(i.get('severity','info')).upper(),'title':i.get('name','Template match'),'asset':x.get('matched-at',t),'status':'Template match — validate manually','evidence':str(x.get('matcher-name','')),'impact':'Automated match is not proof of impact.','remediation':'Review reference and verify before disclosure.'})
   except Exception:pass
 return fs
def report(out,t,prof,hs,fs):
 data={'tool':'VHP NetCheck','version':'2.0','creator':'VHP_Shivam Rathod','target':t,'profile':prof,'generated':dt.datetime.now().astimezone().isoformat(),'hosts':hs,'findings':fs}
 (out/'report.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
 with (out/'findings.csv').open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=['severity','title','asset','status','evidence','impact','remediation']);w.writeheader();w.writerows(fs)
 rows=''.join('<tr>'+''.join('<td>'+str(x.get(k,'')).replace('&','&amp;').replace('<','&lt;')+'</td>' for k in ['severity','title','asset','status','evidence','impact','remediation'])+'</tr>' for x in fs)
 html=f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>VHP NetCheck</title><style>
body{{background:#081321;color:#edf7ff;font:15px system-ui;margin:0}}main{{max-width:1200px;margin:32px auto;padding:0 20px}}header,.card{{background:#11243a;border:1px solid #28415e;border-radius:16px;padding:22px;margin:14px 0}}h1,th{{color:#42d9e9}}.muted{{color:#a9bfd2}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}}.stat{{font-size:27px;font-weight:800}}.scroll{{overflow:auto}}table{{border-collapse:collapse;min-width:850px;width:100%}}td,th{{padding:12px;border-bottom:1px solid #28415e;text-align:left;vertical-align:top;overflow-wrap:anywhere;max-width:400px}}</style></head><body><main>
<header><h1>VHP NetCheck</h1><b>Deep Exposure & Configuration Assessment</b><p class="muted">Created by VHP_Shivam Rathod</p></header>
<div class="grid"><div class="card">Target<br><b>{t}</b></div><div class="card">Profile<div class="stat">{prof.title()}</div></div><div class="card">Hosts up<div class="stat">{sum(h['state']=='up' for h in hs)}</div></div><div class="card">Evidence<div class="stat">{len(fs)}</div></div></div>
<section class="card"><h2>Findings & evidence</h2><p class="muted">Automated observations are leads, not confirmed vulnerabilities.</p><div class="scroll"><table><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Status</th><th>Evidence</th><th>Impact</th><th>Remediation</th></tr>{rows or '<tr><td colspan="7">No findings parsed.</td></tr>'}</table></div></section>
<section class="card"><h2>Before disclosure</h2><ul><li>Confirm exact asset is in current program scope.</li><li>Check automation limits and testing rules.</li><li>Manually validate safely; demonstrate impact without accessing other users’ data.</li><li>Never claim unauthorized access without proof.</li></ul></section></main></body></html>'''
 (out/'report.html').write_text(html,encoding='utf-8')
 (out/'disclosure-draft.md').write_text(f'# Draft security report\nReporter: VHP_Shivam Rathod\nTarget: {t}\n\nOnly describe a manually verified issue. Include safe reproduction steps, evidence, demonstrated impact and remediation. An open port alone is not a vulnerability.\n',encoding='utf-8')
def main():
 banner();ap=argparse.ArgumentParser();ap.add_argument('target',nargs='?');ap.add_argument('--deep',action='store_true');a=ap.parse_args()
 if not shutil.which('nmap'):print(p('Nmap missing: sudo apt install nmap',R));return
 if a.target:t=a.target;prof='deep' if a.deep else 'balanced'
 else:
  print('\n [1] Quick     top 100 TCP ports\n [2] Balanced  top 1000 TCP ports\n [3] Deep      all TCP ports + selected safe configuration checks')
  prof={'1':'quick','2':'balanced','3':'deep'}.get(input('\nSelect profile: ').strip(),'balanced');t=input('Authorized target (IP/CIDR/domain/URL): ')
 try:t,count=target(t)
 except ValueError as e:print(p(str(e),R));return
 print(p(f'\nTarget: {t} | Hosts: {count} | Profile: {prof}',Y))
 if input('Confirm exact target is authorized/in scope? [y/N] ').lower() not in ('y','yes'):print('Cancelled.');return
 if input('Confirm program permits this scan intensity? [y/N] ').lower() not in ('y','yes'):print('Cancelled.');return
 out=Path('reports')/('vhp_'+dt.datetime.now().strftime('%Y%m%d_%H%M%S'));out.mkdir(parents=True,exist_ok=True);start=time.time()
 try:
  scan(t,prof,out);hs,fs=parse(out/'nmap.xml');fs+=nuclei(t,out);report(out,t,prof,hs,fs)
  print(p('\n[3/3] Complete',G+B));print(f"Hosts up: {sum(h['state']=='up' for h in hs)} | Evidence: {len(fs)} | Time: {int(time.time()-start)}s")
  print(p('HTML: '+str(out/'report.html'),C));print('JSON:',out/'report.json','CSV:',out/'findings.csv','Draft:',out/'disclosure-draft.md')
  if input('Open HTML report? [y/N] ').lower() in ('y','yes') and shutil.which('xdg-open'):subprocess.Popen(['xdg-open',str((out/'report.html').resolve())])
 except Exception as e:print(p('Stopped: '+str(e),R));print('Partial output:',out)
if __name__=='__main__':main()
