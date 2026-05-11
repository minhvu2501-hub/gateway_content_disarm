#!/bin/bash
# fix_and_rebuild.sh
# Chay tren Ubuntu VM de fix home.tar va rebuild lab
# Usage: bash fix_and_rebuild.sh

set -e

LAB_DIR=~/labtainer/trunk/labs/gateway_content_disarm
REBUILD=~/labtainer/trunk/scripts/labtainer-student/bin/rebuild.py

echo "========================================================"
echo "  fix_and_rebuild.sh  -  gateway_content_disarm"
echo "========================================================"

# ── Kiem tra lab co ton tai khong ────────────────────────────────
if [ ! -d "$LAB_DIR" ]; then
    echo "[ERROR] Lab directory not found: $LAB_DIR"
    echo "  Run: imodule https://raw.githubusercontent.com/minhvu2501-hub/labtainers-custom/main/gateway_content_disarm.tar"
    exit 1
fi

# ════════════════════════════════════════════════════════════════
#  FIX 1: gateway_proxy home.tar
# ════════════════════════════════════════════════════════════════
echo ""
echo "[1/4] Building gateway_proxy home.tar..."

mkdir -p /tmp/gw_home

# ── icap_scrubber.py ─────────────────────────────────────────────
cat > /tmp/gw_home/icap_scrubber.py << 'PYEOF'
#!/usr/bin/env python3
"""
icap_scrubber.py - WAV Steganography Detector & Sanitizer
Usage: python3 icap_scrubber.py <file.wav>
Output: ~/findings.txt, ~/sanitized.wav
"""
import sys, os, wave, io, math
from collections import Counter

FINDINGS  = os.path.expanduser("~/findings.txt")
SANITIZED = os.path.expanduser("~/sanitized.wav")
KEYWORDS  = ["C2=","TOKEN=","powershell","http","cmd","bash","exec"]

def load_wav(path):
    with wave.open(path,"rb") as f:
        p = f.getparams()
        r = bytearray(f.readframes(f.getnframes()))
    return r, p

def entropy(raw):
    cnt = Counter(raw); n = len(raw)
    return -sum((c/n)*math.log2(c/n) for c in cnt.values() if c)

def lsb_chi(raw):
    lsbs = [b&1 for b in raw]; n = len(lsbs)
    z = lsbs.count(0); e = n/2
    return z/n*100, (n-z)/n*100, ((z-e)**2+(n-z-e)**2)/e

def lower4_chi(raw):
    from collections import Counter as C
    vals = [b&0x0F for b in raw]; cnt = C(vals); e = len(vals)/16
    return sum((cnt.get(v,0)-e)**2/e for v in range(16))

def extract_text(raw, nb=4096):
    bits = "".join(str(b&1) for b in raw[:nb])
    out = []
    for i in range(0,len(bits)-7,8):
        v = int(bits[i:i+8],2)
        out.append(chr(v) if 32<=v<=126 else ("." if v==0 else "?"))
    return "".join(out)

def sanitize(raw, params, path):
    clean = bytearray(b&0xFE for b in raw)
    buf = io.BytesIO()
    with wave.open(buf,"wb") as f:
        f.setparams(params); f.writeframes(bytes(clean))
    with open(path,"wb") as f: f.write(buf.getvalue())

def analyze(path):
    print(f"\n{'='*60}")
    print(f"  WAV ANALYZER  |  {path}")
    print(f"{'='*60}")

    raw, params = load_wav(path)
    print(f"  Size: {len(raw):,} bytes | {params.framerate}Hz | {params.sampwidth*8}-bit")

    detected = False; evidence = []

    ent = entropy(raw)
    print(f"\n  [Entropy]  {ent:.4f} bits/byte", end="  ")
    if ent < 7.5:
        print("<-- SUSPICIOUS"); evidence.append("LOW_ENTROPY"); detected = True
    else: print("(normal)")

    z,o,chi = lsb_chi(raw)
    print(f"\n  [LSB] 0:{z:.2f}%  1:{o:.2f}%  chi2={chi:.2f}", end="  ")
    if chi < 10:
        print("<-- VERY UNIFORM (stego!)"); evidence.append("LSB_CHI2_LOW"); detected = True
    elif chi < 100:
        print("<-- Fairly uniform"); evidence.append("LSB_FAIRLY_UNIFORM")
    else: print("(natural)")

    chi4 = lower4_chi(raw)
    print(f"\n  [4bit chi2] {chi4:.2f}", end="  ")
    if chi4 < 80:
        print("<-- 4-bit stego!"); evidence.append("4BIT_CHI2"); detected = True
    else: print("(normal)")

    text = extract_text(raw)
    pr = sum(1 for c in text if c not in ".?")/max(len(text),1)
    kw = [k for k in KEYWORDS if k.lower() in text.lower()]
    print(f"\n  [LSB text] '{text[:150]}'")
    print(f"  Printable: {pr:.1%}", end="  ")
    if kw:
        print(f"<-- KEYWORDS: {kw}"); evidence.append(f"KEYWORDS:{kw}"); detected = True
    elif pr > 0.70:
        print("<-- High printable"); evidence.append("HIGH_PRINTABLE"); detected = True
    else: print("(no match)")

    print(f"\n{'='*60}")
    print(f"  VERDICT: {'*** LSB DETECTED ***' if detected else 'CLEAN'}")
    print(f"{'='*60}")

    with open(FINDINGS, "a") as f:
        f.write(f"\n=== {os.path.basename(path)} ===\n")
        f.write("WAV_ANALYZED\n")
        if detected:
            f.write("LSB_DETECTED\n")
            for e in evidence: f.write(f"  {e}\n")
        else:
            f.write("CLEAN\n")

    print(f"  [+] Findings -> {FINDINGS}")

    if detected:
        sanitize(raw, params, SANITIZED)
        print(f"  [+] Sanitized -> {SANITIZED} ({os.path.getsize(SANITIZED):,} bytes)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 icap_scrubber.py <file.wav>")
        print("  e.g. python3 icap_scrubber.py lofi_lsb1.wav")
        sys.exit(1)
    t = sys.argv[1]
    if not os.path.exists(t):
        print(f"[ERROR] File not found: {t}"); sys.exit(1)
    analyze(t)
PYEOF

# ── README.txt ───────────────────────────────────────────────────
cat > /tmp/gw_home/README.txt << 'EOF'
===================================================================
  GATEWAY_PROXY  -  LSB Steganography Detection Lab
===================================================================
TASK: Detect steganography in WAV files from fileserver (10.0.0.10)

STEP 1 - Download WAV files:
  wget http://10.0.0.10:8080/lofi_morning.wav
  wget http://10.0.0.10:8080/lofi_evening.wav
  wget http://10.0.0.10:8080/lofi_study.wav
  wget http://10.0.0.10:8080/lofi_chill.wav
  wget http://10.0.0.10:8080/noisy_radio.wav

STEP 2 - Analyze each file:
  python3 icap_scrubber.py lofi_morning.wav
  python3 icap_scrubber.py lofi_evening.wav
  python3 icap_scrubber.py lofi_study.wav
  python3 icap_scrubber.py lofi_chill.wav
  python3 icap_scrubber.py noisy_radio.wav

STEP 3 - Check results:
  cat ~/findings.txt
  ls -lh ~/sanitized.wav

GRADING CRITERIA:
  [x] findings.txt contains WAV_ANALYZED
  [x] findings.txt contains LSB_DETECTED
  [x] sanitized.wav exists and is non-empty
  [x] bash_history contains icap_scrubber.py
===================================================================
EOF

# ── findings.txt (template) ──────────────────────────────────────
cat > /tmp/gw_home/findings.txt << 'EOF'
# WAV Steganography Analysis Results
# Run: python3 icap_scrubber.py <file.wav>
EOF

# ── Pack home.tar ────────────────────────────────────────────────
cd /tmp/gw_home
tar --exclude=home.tar -cvf home.tar .
echo "  gateway_proxy/home.tar contents:"
tar -tf home.tar

mkdir -p "$LAB_DIR/gateway_proxy/home_tar"
cp home.tar "$LAB_DIR/gateway_proxy/home_tar/home.tar"
echo "  [OK] Copied to $LAB_DIR/gateway_proxy/home_tar/home.tar"

# ════════════════════════════════════════════════════════════════
#  FIX 2: fileserver home.tar (4 WAV files)
# ════════════════════════════════════════════════════════════════
echo ""
echo "[2/4] Building fileserver home.tar with 4 WAV files..."

mkdir -p /tmp/fs_home

# Generate 4 WAV files using Python
echo "[2/4] Building fileserver home.tar..."

rm -rf /tmp/fs_home
mkdir -p /tmp/fs_home

cp "$LAB_DIR/fileserver/lofi_morning.wav" /tmp/fs_home/
cp "$LAB_DIR/fileserver/lofi_evening.wav" /tmp/fs_home/
cp "$LAB_DIR/fileserver/lofi_study.wav" /tmp/fs_home/
cp "$LAB_DIR/fileserver/lofi_chill.wav" /tmp/fs_home/
cp "$LAB_DIR/fileserver/noisy_radio.wav" /tmp/fs_home/
cp "$LAB_DIR/fileserver/serve.sh" /tmp/fs_home/

# ── serve.sh ─────────────────────────────────────────────────────
cat > /tmp/fs_home/serve.sh << 'EOF'
#!/bin/bash
cd ~
python3 -m http.server 8080
EOF
chmod +x /tmp/fs_home/serve.sh

# ── Pack home.tar ────────────────────────────────────────────────
cd /tmp/fs_home
tar --exclude=home.tar -cvf home.tar .
echo "  fileserver/home.tar contents:"
tar -tf home.tar

mkdir -p "$LAB_DIR/fileserver/home_tar"
cp home.tar "$LAB_DIR/fileserver/home_tar/home.tar"
echo "  [OK] Copied to $LAB_DIR/fileserver/home_tar/home.tar"

# ════════════════════════════════════════════════════════════════
#  FIX 3: Verify sys.tar exists for each container
# ════════════════════════════════════════════════════════════════
echo ""
echo "[3/4] Ensuring sys.tar files exist..."
for c in gateway_proxy user_pc fileserver; do
    sys_tar="$LAB_DIR/$c/sys_tar/sys.tar"
    if [ ! -f "$sys_tar" ]; then
        mkdir -p "$LAB_DIR/$c/sys_tar"
        tar -cf "$sys_tar" -T /dev/null
        echo "  [+] Created empty sys.tar for $c"
    else
        echo "  [ok] $c/sys_tar/sys.tar exists"
    fi
done

# Lab-level placeholders
[ -f "$LAB_DIR/sys_gateway_content_disarm.tar.gz" ] || \
    tar -czf "$LAB_DIR/sys_gateway_content_disarm.tar.gz" -T /dev/null
[ -f "$LAB_DIR/gateway_content_disarm.tar.gz" ] || \
    tar -czf "$LAB_DIR/gateway_content_disarm.tar.gz" -T /dev/null

# ════════════════════════════════════════════════════════════════
#  FIX 4: Rebuild lab using rebuild.py
# ════════════════════════════════════════════════════════════════
echo ""
echo "[4/4] Rebuilding Docker images with rebuild.py..."
echo ""

cd ~/labtainer/labtainer-student
stoplab 2>/dev/null || true

if [ -f "$REBUILD" ]; then
    python3 "$REBUILD" gateway_content_disarm
else
    echo "[WARN] rebuild.py not found at $REBUILD"
    echo "       Trying alternative location..."
    REBUILD2=$(find ~/labtainer -name "rebuild.py" 2>/dev/null | head -1)
    if [ -n "$REBUILD2" ]; then
        python3 "$REBUILD2" gateway_content_disarm
    else
        echo "[ERROR] rebuild.py not found. Run setup.sh manually."
        exit 1
    fi
fi

# ════════════════════════════════════════════════════════════════
#  VERIFY
# ════════════════════════════════════════════════════════════════
echo ""
echo "========================================================"
echo "  VERIFY: checking home.tar contents"
echo "========================================================"
echo ""
echo "gateway_proxy/home.tar:"
tar -tf "$LAB_DIR/gateway_proxy/home_tar/home.tar"
echo ""
echo "fileserver/home.tar:"
tar -tf "$LAB_DIR/fileserver/home_tar/home.tar"
echo ""
echo "========================================================"
echo "  REBUILD COMPLETE!"
echo ""
echo "  Start the lab:"
echo "    labtainer gateway_content_disarm"
echo ""
echo "  Expected state:"
echo "    gateway_proxy: icap_scrubber.py, README.txt, findings.txt"
echo "    fileserver:    lofi_*.wav (4 files), serve.sh"
echo "========================================================"
