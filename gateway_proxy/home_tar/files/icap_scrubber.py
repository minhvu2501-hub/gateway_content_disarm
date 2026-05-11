import sys, os, wave, io, math
from collections import Counter

FINDINGS  = os.path.expanduser("~/findings.txt")
SANITIZED = os.path.expanduser("~/sanitized.wav")
KEYWORDS  = ["C2=","TOKEN=","powershell","http","cmd"]

def load_wav(p):
    with wave.open(p,"rb") as f: par=f.getparams(); r=bytearray(f.readframes(f.getnframes()))
    return r, par

def entropy(r):
    c=Counter(r); n=len(r)
    return -sum((x/n)*math.log2(x/n) for x in c.values() if x)

def chi(r):
    b=[x&1 for x in r]; n=len(b); z=b.count(0); e=n/2
    return z/n*100,(n-z)/n*100,((z-e)**2+(n-z-e)**2)/e

def chi4(r):
    c=Counter(x&0xF for x in r); e=len(r)/16
    return sum((c.get(v,0)-e)**2/e for v in range(16))

def lsb_text(r,nb=4096):
    bits="".join(str(x&1) for x in r[:nb]); out=[]
    for i in range(0,len(bits)-7,8):
        v=int(bits[i:i+8],2); out.append(chr(v) if 32<=v<=126 else("." if v==0 else"?"))
    return "".join(out)

def sanitize(r,p,path):
    cl=bytearray(x&0xFE for x in r); buf=io.BytesIO()
    with wave.open(buf,"wb") as f: f.setparams(p); f.writeframes(bytes(cl))
    open(path,"wb").write(buf.getvalue())

def analyze(path):
    print(f"\n{'='*55}\n  WAV ANALYZER: {path}\n{'='*55}")
    r,p=load_wav(path)
    print(f"  {len(r):,} bytes | {p.framerate}Hz | {p.sampwidth*8}-bit")
    det=False; ev=[]

    ent=entropy(r); flag=ent<7.5
    print(f"\n  Entropy: {ent:.4f}  {'<-- SUSPICIOUS' if flag else '(normal)'}")
    if flag: det=True; ev.append("LOW_ENTROPY")

    z,o,c=chi(r); flag=c<10
    print(f"  LSB chi2: {c:.2f}  (0:{z:.1f}% 1:{o:.1f}%)  {'<-- STEGO!' if flag else '(normal)'}")
    if flag: det=True; ev.append("LSB_CHI2_LOW")
    elif c<100: ev.append("LSB_FAIRLY_UNIFORM")

    c4=chi4(r); flag=c4<80
    print(f"  4bit chi2: {c4:.2f}  {'<-- 4-bit stego!' if flag else '(normal)'}")
    if flag: det=True; ev.append("4BIT_CHI2")

    t=lsb_text(r); pr=sum(1 for x in t if x not in ".?")/max(len(t),1)
    kw=[k for k in KEYWORDS if k.lower() in t.lower()]
    print(f"  LSB text: '{t[:120]}'")
    print(f"  Printable: {pr:.1%}  {f'<-- KEYWORDS:{kw}' if kw else ''}")
    if kw: det=True; ev.append(f"KEYWORDS:{kw}")
    elif pr>0.7: det=True; ev.append("HIGH_PRINTABLE")

    print(f"\n  VERDICT: {'*** LSB DETECTED ***' if det else 'CLEAN'}\n{'='*55}")

    with open(FINDINGS,"a") as f:
        f.write(f"\n=== {os.path.basename(path)} ===\n")
        f.write("WAV_ANALYZED\n")
        if det:
            f.write("LSB_DETECTED\n")
            for e in ev: f.write(f"  {e}\n")
        else: f.write("CLEAN\n")
    print(f"  [+] {FINDINGS}")

    if det:
        sanitize(r,p,SANITIZED)
        print(f"  [+] {SANITIZED} ({os.path.getsize(SANITIZED):,} bytes)")

if __name__=="__main__":
    if len(sys.argv)<2: print("Usage: python3 icap_scrubber.py <file.wav>"); sys.exit(1)
    t=sys.argv[1]
    if not os.path.exists(t): print(f"ERROR: {t} not found"); sys.exit(1)
    analyze(t)
