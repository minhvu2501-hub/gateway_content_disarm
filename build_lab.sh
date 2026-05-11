#!/bin/bash
# build_lab.sh  -  Đóng gói lab gateway_content_disarm cho Labtainer
# Chạy script này trên Ubuntu (VMware) trước khi copy lab vào Labtainer.
#
# Script thực hiện:
#   1) Tạo file lofi_chill.wav (infected) bằng gen_lofi_chill.py
#   2) Đóng gói home.tar cho mỗi container
#   3) Tạo sys.tar rỗng cho mỗi container
#   4) Tạo sys_gateway_content_disarm.tar.gz rỗng (lab-level sys tar)
#
# Sau khi chạy xong, copy toàn bộ thư mục vào:
#   ~/labtainer/trunk/labs/gateway_content_disarm/

set -e
LABDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$LABDIR"

echo "========================================================"
echo "  gateway_content_disarm  —  Lab Builder"
echo "========================================================"

# ── Bước 1: Tạo file WAV infected ───────────────────────────────
echo ""
echo "[1/4] Tạo lofi_chill.wav (infected)..."
python3 gen_lofi_chill.py
echo "    Done."

# ── Bước 2: Đóng gói home.tar cho từng container ────────────────
echo ""
echo "[2/4] Đóng gói home.tar files..."

pack_home() {
    local container="$1"
    local files_dir="$LABDIR/$container/home_tar/files"
    local tar_path="$LABDIR/$container/home_tar/home.tar"

    if [ -d "$files_dir" ]; then
        tar -cf "$tar_path" -C "$files_dir" .
        echo "    [OK] $container/home_tar/home.tar"
    else
        echo "    [SKIP] $container/home_tar/files/ not found"
    fi
}

pack_home "gateway_proxy"
pack_home "user_pc"
pack_home "fileserver"

# ── Bước 3: Tạo sys.tar rỗng cho mỗi container ──────────────────
echo ""
echo "[3/4] Tạo sys.tar files (empty)..."

make_empty_sys_tar() {
    local container="$1"
    local sys_dir="$LABDIR/$container/sys_tar"
    mkdir -p "$sys_dir"
    # Tạo tar rỗng (không có file nào)
    tar -cf "$sys_dir/sys.tar" -T /dev/null
    echo "    [OK] $container/sys_tar/sys.tar"
}

make_empty_sys_tar "gateway_proxy"
make_empty_sys_tar "user_pc"
make_empty_sys_tar "fileserver"

# ── Bước 4: Tạo lab-level sys tar rỗng ──────────────────────────
echo ""
echo "[4/4] Tạo sys_gateway_content_disarm.tar.gz..."
tar -czf "$LABDIR/sys_gateway_content_disarm.tar.gz" -T /dev/null
echo "    [OK] sys_gateway_content_disarm.tar.gz"

# Tạo các file tar.gz placeholder cho từng container
tar -czf "$LABDIR/gateway_content_disarm.tar.gz" -T /dev/null
echo "    [OK] gateway_content_disarm.tar.gz"

echo ""
echo "========================================================"
echo "  BUILD COMPLETE!"
echo ""
echo "  Bước tiếp theo:"
echo "    sudo cp -r $LABDIR ~/labtainer/trunk/labs/gateway_content_disarm"
echo "    cd ~/labtainer/trunk/labs"
echo "    labtainer gateway_content_disarm"
echo "========================================================"
