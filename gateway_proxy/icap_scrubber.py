import sys,os,wave,io,math,struct
from collections import Counter
FINDINGS=os.path.expanduser("~/findings.txt")
SANITIZED=os.path.expanduser("~/sanitized.wav")
def load_wav(p):
    with wave.open(p,"rb") as f: par=f.getparams();r=bytearray(f.readframes(f.getnframes()))
    return r,par
def entropy(r):
    c=Counter(r);n=len(r)
    return -sum((x/n)*math.log2(x/n) for x in c.values() if x)
def lsb_chi(r):
    b=[x&1 for x in r];n=len(b);z=b.count(0);e=n/2
    return z/n*100,(n-z)/n*100,((z-e)**2+(n-z-e)**2)/e
def chi4(r):
    c=Counter(x&0xF for x in r);e=len(r)/16
    return sum((c.get(v,0)-e)**2/e for v in range(16))
def run_var(r):
    b=[x&1 for x in r[:20000]];runs=[];cur=1
    for i in range(1,len(b)):
        if b[i]==b[i-1]:cur+=1
        else:runs.append(cur);cur=1
    if not runs:return 0
    m=sum(runs)/len(runs)
    return sum((x-m)**2 for x in runs)/len(runs)
def lsb_text(r,n=512):
    bits="".join(str(x&1) for x in r[:n*8]);chars=[]
    for i in range(0,len(bits)-7,8):
        v=int(bits[i:i+8],2);chars.append(chr(v) if 32<=v<=126 else("." if v==0 else "?"))
    t="".join(chars)
    good = sum(
       1 for c in t
       if c.isalnum() or c in " =:/._-"
    )

    pr = good / max(len(t),1)
    kw=[k for k in ["C2=","TOKEN=","powershell","http://","cmd","exec"] if k.lower() in t.lower()]
    return t,pr,kw
def sanitize(r,p,path):
    cl=bytearray(x&0xFE for x in r);buf=io.BytesIO()
    with wave.open(buf,"wb") as f:f.setparams(p);f.writeframes(bytes(cl))
    open(path,"wb").write(buf.getvalue())
def risk(chi2,chi4v,ent,pr,kw,rv):
    s=0;ev=[]
    if chi2<200:s+=55;ev.append(f"LSB_CHI2_CRITICAL({chi2:.1f})")
    elif chi2<2000:s+=25;ev.append(f"LSB_CHI2_LOW({chi2:.1f})")
    elif chi2<5000:s+=10;ev.append(f"LSB_CHI2_MOD({chi2:.1f})")
    if chi4v<50:s+=35;ev.append(f"4BIT_CRITICAL({chi4v:.1f})")
    elif chi4v<700:s+=20;ev.append(f"4BIT_LOW({chi4v:.1f})")
    elif chi4v<5000:s+=8;ev.append(f"4BIT_MOD({chi4v:.1f})")
    if ent<7.2:s+=15;ev.append(f"LOW_ENTROPY({ent:.3f})")
    if kw:s+=20;ev.append(f"KEYWORDS:{kw}")
    elif pr>0.75:s+=10;ev.append(f"HIGH_PRINT({pr:.0%})")
    if rv<1.2:s+=10;ev.append(f"LOW_RUNVAR({rv:.2f})")
    return min(s,100),ev
def verdict(s):
    if s>=70:return "BLOCK","*** MALWARE DETECTED — FILE BLOCKED ***"
    elif s>=40:return "SANITIZE","SUSPICIOUS — sanitizing before forwarding"
    return "ALLOW","CLEAN — forwarding to user"
def analyze(path):
    W=60;print(f"\n{'='*W}\n  GATEWAY CDR ANALYZER  |  {os.path.basename(path)}\n{'='*W}")
    try:r,p=load_wav(path)
    except Exception as e:print(f"ERROR: {e}");sys.exit(1)
    print(f"  {len(r):,} bytes | {p.framerate}Hz | {p.sampwidth*8}-bit")
    ent=entropy(r);z,o,c2=lsb_chi(r);c4=chi4(r);rv=run_var(r);t,pr,kw=lsb_text(r)
    print(f"\n  Entropy  : {ent:.4f}  {'<-- ANOMALY' if ent<7.2 else '(normal)'}")
    print(f"  LSB chi2 : {c2:.2f}  {'<-- CRITICAL' if c2<200 else ('<-- LOW' if c2<2000 else '(normal)')}")
    print(f"  4bit chi2: {c4:.2f}  {'<-- CRITICAL' if c4<50 else ('<-- LOW' if c4<700 else '(normal)')}")
    print(f"  Run var  : {rv:.3f}  {'<-- LOW' if rv<1.2 else '(normal)'}")
    print(f"  LSB text : '{t[:100]}'")
    print(f"  Printable: {pr:.1%}  {f'KEYWORDS:{kw}' if kw else ''}")
    sc,ev=risk(c2,c4,ent,pr,kw,rv)
    act,msg=verdict(sc)
    bar="X"*(sc//5)+"."*(20-sc//5)
    print(f"\n  {'='*W}")
    print(f"  Risk Score : {sc}/100  [{bar}]")
    print(f"  Action     : {act}")
    print(f"  Reason     : {msg}")
    print(f"  Evidence   : {', '.join(ev) if ev else 'none'}")
    print(f"  {'='*W}")
    with open(FINDINGS,"a") as f:
        f.write(
             f"\n=== {os.path.basename(path)} ===\n"
             f"WAV_ANALYZED\n"
             f"RISK_SCORE={sc}\n"
             f"ACTION={act}\n"
        )
        if sc>=40:f.write("LSB_DETECTED\n")
        else:f.write("CLEAN\n")
    print(f"  [+] {FINDINGS}")
    if act in("SANITIZE","BLOCK"):
        sanitize(r,p,SANITIZED)
        print(f"  [+] {SANITIZED} ({os.path.getsize(SANITIZED):,} bytes)")
    return sc,act
if __name__=="__main__":
    if len(sys.argv)<2:print("Usage: python3 icap_scrubber.py <file.wav>");sys.exit(1)
    if not os.path.exists(sys.argv[1]):print(f"ERROR: {sys.argv[1]} not found");sys.exit(1)
    analyze(sys.argv[1])
