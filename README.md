# gateway_content_disarm — Labtainer Lab

> **Kịch bản:** Cổng Mạng Vô Trùng (Gateway Content Disarm) chặn Stegomalware  
> **Framework:** [Labtainers](https://nps.edu/web/c3o/labtainers) (NPS)

## Mô tả

Sinh viên học cách thiết lập cơ chế kiểm tra và "làm sạch" dữ liệu (Content Disarm) tự động tại Proxy/Gateway để chặn kỹ thuật Stegomalware (giấu C2 payload trong file âm thanh WAV).

## Kiến trúc mạng

```
[fileserver 10.0.0.10]  ←── HTTP server phục vụ lofi_chill.wav (bị nhiễm LSB)
        ↓  wget qua proxy
[gateway_proxy 10.0.0.1]  ←── Squid Proxy (port 3128) + ICAP Scrubber (port 1344)
        ↓  file đã làm sạch
[user_pc 10.0.0.5]  ←── Tải file → chạy dropper.py → FAIL (C2 bị phá)
```

## Cài đặt & Chạy

### Yêu cầu
- Ubuntu 20.04+ với [Labtainers đã cài](https://nps.edu/web/c3o/labtainers)
- Python 3.x
- Docker

### Bước 1: Clone repo
```bash
git clone https://github.com/minhvu2501-hub/labtainers-custom.git
cd labtainers-custom
```

### Bước 2: Build lab assets
```bash
# Tạo file WAV bị nhiễm và đóng gói home.tar cho từng container
bash build_lab.sh
```

### Bước 3: Copy vào thư mục Labtainer
```bash
cp -r . ~/labtainer/trunk/labs/gateway_content_disarm
```

### Bước 4: Khởi động lab
```bash
cd ~/labtainer/trunk/labs
labtainer gateway_content_disarm
```

---

## Nhiệm vụ sinh viên

### Trên `gateway_proxy` (10.0.0.1)

**Bước 1:** Hoàn thiện hàm `scrub_wav_lsb()` trong `~/icap_scrubber.py`

```python
def scrub_wav_lsb(wav_bytes: bytes) -> bytes:
    inp = io.BytesIO(wav_bytes)
    with wave.open(inp, 'rb') as f:
        params = f.getparams()
        raw    = bytearray(f.readframes(f.getnframes()))

    for i in range(len(raw)):
        raw[i] = raw[i] & 0xFE   # Xóa bit LSB về 0

    out = io.BytesIO()
    with wave.open(out, 'wb') as f:
        f.setparams(params)
        f.writeframes(bytes(raw))
    return out.getvalue()
```

**Bước 2:** Khởi động services
```bash
bash ~/start_services.sh
```

### Trên `user_pc` (10.0.0.5)

**Bước 3:** Tải file qua proxy
```bash
wget --proxy=http://10.0.0.1:3128 http://10.0.0.10/lofi_chill.wav
```

**Bước 4:** Kiểm chứng phòng thủ
```bash
python3 dropper.py lofi_chill.wav
# Kết quả mong đợi: "Garbage extracted. Payload corrupted. Aborting."
```

---

## Tiêu chí Pass

| Tiêu chí | Kiểm tra |
|---|---|
| `lofi_chill.wav` tồn tại và > 0 bytes | `results.config: wav_exists` |
| `dropper.py` trả về exit code 1 (FAIL) | `results.config: dropper_failed` |
| Đã chạy `icap_scrubber.py` | `.bash_history` |
| Đã chạy `squid` | `.bash_history` |

## Cấu trúc thư mục

```
gateway_content_disarm/
├── config/                  Cấu hình Labtainer
├── dockerfiles/             3 Dockerfile (gateway_proxy, user_pc, fileserver)
├── instr_config/            Hệ thống chấm điểm tự động
├── gateway_proxy/           Home files cho container gateway_proxy
│   └── home_tar/files/
│       ├── icap_scrubber.py ← Sinh viên hoàn thiện hàm này
│       ├── squid.conf
│       └── start_services.sh
├── user_pc/                 Home files cho container user_pc
│   └── home_tar/files/
│       └── dropper.py       ← Grading tool
├── fileserver/              Home files cho container fileserver
├── gen_lofi_chill.py        Tạo WAV bị nhiễm (instructor only)
└── build_lab.sh             Build script
```
