#!/usr/bin/env python3
import argparse, pathlib, subprocess, os
CRITICAL=("crates/runonmine-core/src/policy.rs","crates/runonmine-core/src/storage.rs","crates/runonmine-core/src/approval.rs","crates/runonmine-oauth/src/","crates/runonmine-mcp/src/auth")
def parse(path):
 files={}; current=None
 for raw in pathlib.Path(path).read_text(errors='replace').splitlines():
  if raw.startswith('SF:'): current=raw[3:].replace('\\','/'); files.setdefault(current,{})
  elif raw.startswith('DA:') and current:
   line,hits=raw[3:].split(',')[:2]; files[current][int(line)]=int(hits)
 return files
def ratio(values):
 values=list(values); return 100.0 if not values else 100.0*sum(v>0 for v in values)/len(values)
def changed_lines(base):
 out=subprocess.check_output(['git','diff','--unified=0',f'{base}...HEAD','--','*.rs'],text=True)
 result={}; current=None
 for line in out.splitlines():
  if line.startswith('+++ b/'): current=line[6:]; result.setdefault(current,set())
  elif line.startswith('@@') and current:
   chunk=line.split('+',1)[1].split(' ',1)[0]; parts=chunk.split(','); start=int(parts[0]); count=int(parts[1]) if len(parts)>1 else 1
   result[current].update(range(start,start+count))
 return result
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('lcov'); ap.add_argument('--global',dest='global_',type=float,required=True); ap.add_argument('--critical',type=float,required=True); ap.add_argument('--changed',type=float,required=True); a=ap.parse_args()
 files=parse(a.lcov); errors=[]
 global_ratio=ratio(h for lines in files.values() for h in lines.values()); print(f'global_line_coverage={global_ratio:.2f}%')
 if global_ratio<a.global_: errors.append(f'global {global_ratio:.2f}% < {a.global_:.2f}%')
 critical=[h for path,lines in files.items() if any(path.replace('\\','/').endswith(prefix) or '/'+prefix in path.replace('\\','/') for prefix in CRITICAL) for h in lines.values()]
 critical_ratio=ratio(critical); print(f'critical_line_coverage={critical_ratio:.2f}%')
 if critical_ratio<a.critical: errors.append(f'critical {critical_ratio:.2f}% < {a.critical:.2f}%')
 base=os.environ.get('BASE_SHA','').strip()
 if base:
  changed=changed_lines(base); hits=[]
  for source,lines in changed.items():
   covered=next((v for p,v in files.items() if p.endswith('/'+source) or p==source),{})
   hits.extend(covered[line] for line in lines if line in covered)
  changed_ratio=ratio(hits); print(f'changed_executable_line_coverage={changed_ratio:.2f}%')
  if hits and changed_ratio<a.changed: errors.append(f'changed {changed_ratio:.2f}% < {a.changed:.2f}%')
 if errors: raise SystemExit('coverage ratchet failed: '+'; '.join(errors))
if __name__=='__main__': main()
