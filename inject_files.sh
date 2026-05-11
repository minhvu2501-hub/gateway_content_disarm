#!/bin/bash
# inject_files.sh
# Inject files TRUC TIEP vao container dang chay - khong can rebuild
# Usage: bash inject_files.sh
# Chay SAU KHI: labtainer gateway_content_disarm

set -e

echo "========================================================"
echo "  inject_files.sh  -  Fix running containers"
echo "========================================================"

# ── Tim container names ──────────────────────────────────────────
find_container() {
    docker ps --format "{{.Names}}" | grep -i "$1" | head -1
}

GW=$(find_container "gateway_proxy")
FS=$(find_container "fileserver")
UC=$(find_container "user_pc")

if [ -z "$GW" ] || [ -z "$FS" ]; then
    echo "[ERROR] Containers not running!"
    echo "  Run: labtainer gateway_content_disarm"
    echo "  Then: bash inject_files.sh"
    exit 1
fi

echo "  gateway_proxy : $GW"
echo "  fileserver    : $FS"
[ -n "$UC" ] && echo "  user_pc       : $UC"
echo ""

# ════════════════════════════════════════════════════════════════
#  FIX 1: gateway_proxy - inject icap_scrubber.py + README + findings
# ════════════════════════════════════════════════════════════════
echo "[1/3] Fixing gateway_proxy..."

docker exec "$GW" bash -c 'cat > /home/ubuntu/icap_scrubber.py' << 'PYEOF'
#!/usr/bin/env python3
"""
icap_scrubber.py - WAV Steganography Detector & Sanitizer
Usage: python3 icap_scrubber.py <file.wav>
"""
import sys, os, wave, io, math
from collections import Counter

FINDINGS  = os.path.expanduser("~/findings.txt")
SANITIZED = os.path.expanduser("~/sanitized.wav")
KEYWORDS  = ["C2=","TOKEN=","powershell","http","cmd","bash"]

def load_wav(path):
    with wave.open(path,"rb") as f:
        p = f.getparams(); r = bytearray(f.readframes(f.getnframes()))
    return r, p

def entropy(raw):
    cnt = Counter(raw); n = len(raw)
    return -sum((c/n)*math.log2(c/n) for c in cnt.values() if c)

def lsb_chi(raw):
    lsbs=[b&1 for b in raw]; n=len(lsbs); z=lsbs.count(0); e=n/2
    return z/n*100,(n-z)/n*100,((z-e)**2+(n-z-e)**2)/e

def lower4_chi(raw):
    from collections import Counter as C
    vals=[b&0x0F for b in raw]; cnt=C(vals); e=len(vals)/16
    return sum((cnt.get(v,0)-e)**2/e for v in range(16))

def extract_text(raw, nb=4096):
    bits="".join(str(b&1) for b in raw[:nb])
    out=[]
    for i in range(0,len(bits)-7,8):
        v=int(bits[i:i+8],2)
        out.append(chr(v) if 32<=v<=126 else("." if v==0 else"?"))
    return "".join(out)

def sanitize(raw, params, path):
    clean=bytearray(b&0xFE for b in raw)
    buf=io.BytesIO()
    with wave.open(buf,"wb") as f: f.setparams(params); f.writeframes(bytes(clean))
    with open(path,"wb") as f: f.write(buf.getvalue())

def analyze(path):
    W=60
    print(f"\n{'='*W}\n  WAV ANALYZER  |  {path}\n{'='*W}")
    raw,params=load_wav(path)
    print(f"  Size: {len(raw):,} bytes | {params.framerate}Hz | {params.sampwidth*8}-bit")
    detected=False; evidence=[]

    ent=entropy(raw)
    print(f"\n  [Entropy]  {ent:.4f}",end="  ")
    if ent<7.5: print("<-- SUSPICIOUS"); evidence.append("LOW_ENTROPY"); detected=True
    else: print("(normal)")

    z,o,chi=lsb_chi(raw)
    print(f"\n  [LSB] 0:{z:.2f}%  1:{o:.2f}%  chi2={chi:.2f}",end="  ")
    if chi<10: print("<-- VERY UNIFORM (stego!)"); evidence.append("LSB_CHI2_LOW"); detected=True
    elif chi<100: print("<-- Fairly uniform"); evidence.append("LSB_FAIRLY_UNIFORM")
    else: print("(natural)")

    chi4=lower4_chi(raw)
    print(f"\n  [4bit chi2] {chi4:.2f}",end="  ")
    if chi4<80: print("<-- 4-bit stego!"); evidence.append("4BIT_CHI2"); detected=True
    else: print("(normal)")

    text=extract_text(raw)
    pr=sum(1 for c in text if c not in ".?")/max(len(text),1)
    kw=[k for k in KEYWORDS if k.lower() in text.lower()]
    print(f"\n  [LSB text] '{text[:150]}'")
    print(f"  Printable: {pr:.1%}",end="  ")
    if kw: print(f"<-- KEYWORDS: {kw}"); evidence.append(f"KEYWORDS:{kw}"); detected=True
    elif pr>0.70: print("<-- High printable"); evidence.append("HIGH_PRINTABLE"); detected=True
    else: print("(no match)")

    print(f"\n{'='*W}")
    print(f"  VERDICT: {'*** LSB DETECTED ***' if detected else 'CLEAN'}")
    print(f"{'='*W}")

    with open(FINDINGS,"a") as f:
        f.write(f"\n=== {os.path.basename(path)} ===\n")
        f.write("WAV_ANALYZED\n")
        if detected:
            f.write("LSB_DETECTED\n")
            for e in evidence: f.write(f"  {e}\n")
        else: f.write("CLEAN\n")
    print(f"  [+] Findings -> {FINDINGS}")

    if detected:
        sanitize(raw,params,SANITIZED)
        print(f"  [+] Sanitized -> {SANITIZED} ({os.path.getsize(SANITIZED):,} bytes)")

if __name__=="__main__":
    if len(sys.argv)<2:
        print("Usage: python3 icap_scrubber.py <file.wav>"); sys.exit(1)
    t=sys.argv[1]
    if not os.path.exists(t): print(f"[ERROR] Not found: {t}"); sys.exit(1)
    analyze(t)
PYEOF

docker exec "$GW" bash -c 'cat > /home/ubuntu/README.txt << "EOF"
===================================================================
  GATEWAY_PROXY  -  LSB Steganography Detection Lab
===================================================================
STEP 1 - Download WAV files from fileserver:
  wget http://10.0.0.10/lofi_clean.wav
  wget http://10.0.0.10/lofi_lsb1.wav
  wget http://10.0.0.10/lofi_lsb4.wav
  wget http://10.0.0.10/lofi_hash.wav

STEP 2 - Analyze each file:
  python3 icap_scrubber.py lofi_clean.wav
  python3 icap_scrubber.py lofi_lsb1.wav
  python3 icap_scrubber.py lofi_lsb4.wav
  python3 icap_scrubber.py lofi_hash.wav

STEP 3 - Check results:
  cat ~/findings.txt
  ls -lh ~/sanitized.wav

STEP 4 - Save history:
  history -w
===================================================================
EOF'

docker exec "$GW" bash -c 'echo "# WAV Steganography Analysis Results" > /home/ubuntu/findings.txt'
docker exec "$GW" bash -c 'chown ubuntu:ubuntu /home/ubuntu/icap_scrubber.py /home/ubuntu/README.txt /home/ubuntu/findings.txt 2>/dev/null || true'

echo "  [OK] gateway_proxy: icap_scrubber.py + README.txt + findings.txt"
docker exec "$GW" ls /home/ubuntu/

# ════════════════════════════════════════════════════════════════
#  FIX 2: fileserver - generate 4 WAV files
# ════════════════════════════════════════════════════════════════
echo ""
echo "[2/3] Fixing fileserver - generating 4 WAV files..."

docker exec "$FS" python3 << 'PYEOF'
import wave, struct, math, random, io, hashlib, os

HOME = "/home/ubuntu"
PAYLOADS = {
    "lofi_clean.wav" : None,
    "lofi_lsb1.wav"  : ("lsb1",  "C2=185.22.10.4:4444" * 300 + "###END###"),
    "lofi_lsb4.wav"  : ("lsb4",  ("powershell -enc " + "A"*200)*20 + "###END###"),
    "lofi_hash.wav"  : ("hash",  "TOKEN=ABCD-1234-XYZ" * 300 + "###END###"),
}

def cover():
    rng = random.Random(42); frames = []
    for i in range(6*44100):
        t = i/44100
        v = (math.sin(2*math.pi*261.63*t)*0.40+math.sin(2*math.pi*329.63*t)*0.20+
             math.sin(2*math.pi*392.00*t)*0.15+rng.uniform(-0.05,0.05))
        s = int(round(v*26000/2)*2); s=max(-32768,min(32766,s))
        if rng.random()<0.28: s=min(32767,s+1)
        frames.append(struct.pack("<h",s))
    buf=io.BytesIO()
    with wave.open(buf,"w") as f:
        f.setnchannels(1);f.setsampwidth(2);f.setframerate(44100);f.writeframes(b"".join(frames))
    return buf.getvalue()

def rw(d):
    buf=io.BytesIO(d)
    with wave.open(buf,"rb") as f: p=f.getparams();r=bytearray(f.readframes(f.getnframes()))
    return r,p

def tw(r,p):
    buf=io.BytesIO()
    with wave.open(buf,"wb") as f: f.setparams(p);f.writeframes(bytes(r))
    return buf.getvalue()

def bits(t): return "".join(format(ord(c),"08b") for c in t)

def lsb1(wav,s):
    r,p=rw(wav);b=bits(s)[:len(r)]
    for i,x in enumerate(b): r[i]=(r[i]&0xFE)|int(x)
    return tw(r,p)

def lsb4(wav,s):
    r,p=rw(wav);b=bits(s)
    for i in range(0,min(len(b),len(r)*4),4):
        idx=i//4
        if idx>=len(r): break
        r[idx]=(r[idx]&0xF0)|int(b[i:i+4].ljust(4,"0"),2)
    return tw(r,p)

def lsbhash(wav,s,key="lab_key_2024"):
    r,p=rw(wav);n=len(r)
    rng=random.Random(int(hashlib.sha256(key.encode()).hexdigest(),16))
    pos=list(range(n));rng.shuffle(pos);b=bits(s)
    for i,x in enumerate(b):
        if i>=n: break
        r[pos[i]]=(r[pos[i]]&0xFE)|int(x)
    return tw(r,p)

c = cover()
for fname,(method,payload) in PAYLOADS.items() if isinstance(PAYLOADS.items(),object) else []:
    pass

c = cover()
for fname, info in PAYLOADS.items():
    if info is None:
        data = c
    elif info[0] == "lsb1":
        data = lsb1(c, info[1])
    elif info[0] == "lsb4":
        data = lsb4(c, info[1])
    else:
        data = lsbhash(c, info[1])
    path = f"{HOME}/{fname}"
    with open(path,"wb") as f: f.write(data)
    os.chmod(path, 0o644)
    print(f"  [+] {fname:20s}  {len(data):>9,} bytes")

# serve.sh
with open(f"{HOME}/serve.sh","w") as f:
    f.write("#!/bin/bash\ncd ~\npython3 -m http.server 80\n")
os.chmod(f"{HOME}/serve.sh", 0o755)
print("  [+] serve.sh")
print("  Done!")
PYEOF

echo "  [OK] fileserver contents:"
docker exec "$FS" ls /home/ubuntu/

# ════════════════════════════════════════════════════════════════
#  FIX 3: user_pc - remove dropper.py if present
# ════════════════════════════════════════════════════════════════
if [ -n "$UC" ]; then
    echo ""
    echo "[3/3] Fixing user_pc..."
    docker exec "$UC" bash -c 'rm -f /home/ubuntu/dropper.py /home/ubuntu/lofi_chill.wav 2>/dev/null; echo "  Cleaned old files"'
    echo "  [OK] user_pc contents:"
    docker exec "$UC" ls /home/ubuntu/
fi

echo ""
echo "========================================================"
echo "  INJECT COMPLETE!"
echo ""
echo "  Test flow:"
echo "  1. [fileserver]    ./serve.sh"
echo "  2. [gateway_proxy] wget http://10.0.0.10/lofi_lsb1.wav"
echo "  3. [gateway_proxy] python3 icap_scrubber.py lofi_lsb1.wav"
echo "  4. [gateway_proxy] cat ~/findings.txt"
echo "========================================================"
