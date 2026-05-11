#!/bin/bash
# setup.sh  -  Build Docker images locally for gateway_content_disarm lab
#
# Chạy script này SAU KHI imodule đã tải lab về:
#   bash ~/labtainer/trunk/labs/gateway_content_disarm/setup.sh
#
# Script sẽ:
#   1) Tìm registry và base image đang dùng
#   2) Build 3 Docker images từ Dockerfiles
#   3) Xác nhận build thành công
#   4) Hướng dẫn chạy lab

set -e

LAB="gateway_content_disarm"
REG="ptitwibu"

# Tự tìm thư mục lab
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$SCRIPT_DIR"

echo "========================================================"
echo "  $LAB  —  Local Docker Image Builder"
echo "========================================================"
echo ""
echo "Lab directory: $LAB_DIR"
echo ""

# ── Kiểm tra base image có sẵn không ───────────────────────────
echo "[Check] Tìm base image labtainer.base2..."
if docker images | grep -q "labtainer.base2"; then
    BASE_REG=$(docker images | grep "labtainer.base2" | awk '{print $1}' | head -1 | sed 's/\/labtainer.base2//')
    echo "  [OK] Found base image: ${BASE_REG}/labtainer.base2"
    REG="$BASE_REG"
else
    echo "  [WARN] labtainer.base2 not found locally."
    echo "         Trying to pull from $REG ..."
    docker pull ${REG}/labtainer.base2 || {
        echo "  [FAIL] Cannot pull base image. Please check network."
        exit 1
    }
fi

# Build context = thư mục CHA của lab (~/labtainer/trunk/labs/)
# labdir phải là đường dẫn TƯƠNG ĐỐI để Docker ADD hoạt động đúng
PARENT_DIR="$(dirname "$LAB_DIR")"

# ── Tạo các file bắt buộc trước khi build ────────────────────────
prepare_assets() {
    # sys.tar rỗng cho từng container
    for c in gateway_proxy user_pc fileserver; do
        local sys_tar="${LAB_DIR}/${c}/sys_tar/sys.tar"
        if [ ! -f "$sys_tar" ]; then
            mkdir -p "${LAB_DIR}/${c}/sys_tar"
            tar -cf "$sys_tar" -T /dev/null
            echo "  [+] Created empty sys.tar for ${c}"
        fi

        # home.tar nếu chưa có
        local home_tar="${LAB_DIR}/${c}/home_tar/home.tar"
        if [ ! -f "$home_tar" ]; then
            mkdir -p "${LAB_DIR}/${c}/home_tar"
            if [ -d "${LAB_DIR}/${c}/home_tar/files" ]; then
                tar -cf "$home_tar" -C "${LAB_DIR}/${c}/home_tar/files" .
                echo "  [+] Packed home.tar for ${c}"
            else
                tar -cf "$home_tar" -T /dev/null
                echo "  [+] Created empty home.tar for ${c}"
            fi
        fi
    done

    # Lab-level tarballs (required by Dockerfiles)
    [ -f "${LAB_DIR}/sys_${LAB}.tar.gz" ] || \
        tar -czf "${LAB_DIR}/sys_${LAB}.tar.gz" -T /dev/null && \
        echo "  [+] Created sys_${LAB}.tar.gz"
    [ -f "${LAB_DIR}/${LAB}.tar.gz" ] || \
        tar -czf "${LAB_DIR}/${LAB}.tar.gz" -T /dev/null && \
        echo "  [+] Created ${LAB}.tar.gz"
}

# ── Hàm build image ─────────────────────────────────────────────
build_image() {
    local container="$1"
    local image_tag="${REG}/${LAB}.${container}.student"
    local dockerfile="${LAB_DIR}/dockerfiles/Dockerfile.${LAB}.${container}.student"

    echo ""
    echo "[Build] ${container}  ->  ${image_tag}"

    # Always remove old image to force rebuild with latest home.tar
    docker rmi "${image_tag}" 2>/dev/null && echo "  [rm] Removed old image" || true

    # ── KEY FIX: build context = PARENT dir, labdir = RELATIVE path ──
    # Dockerfile: ADD $labdir/$imagedir/sys_tar/sys.tar /
    # → ADD gateway_content_disarm/gateway_proxy/sys_tar/sys.tar /
    # → resolved relative to PARENT_DIR (~/labtainer/trunk/labs/) ✓
    docker build \
        --build-arg registry="${REG}" \
        --build-arg lab="${LAB}" \
        --build-arg labdir="${LAB}" \
        --build-arg imagedir="${container}" \
        --build-arg user_name="ubuntu" \
        --build-arg password="ubuntu" \
        --build-arg apt_source="ubuntu" \
        --build-arg version="1.0" \
        -t "${image_tag}" \
        -f "${dockerfile}" \
        "${PARENT_DIR}" \
        && echo "  [OK] ${image_tag}" \
        || { echo "  [FAIL] Build failed for ${container}"; exit 1; }
}

# ── Prepare all required asset files ────────────────────────────
echo ""
echo "[Prepare] Checking/creating required asset files..."
prepare_assets

# ── Build all containers ─────────────────────────────────────────
build_image "gateway_proxy"
build_image "user_pc"
build_image "fileserver"

# ── Xác nhận ────────────────────────────────────────────────────
echo ""
echo "========================================================"
echo "  BUILD COMPLETE! Images created:"
docker images | grep "${LAB}" | awk '{printf "  %-55s %s\n", $1":"$2, $7" "$8}'
echo ""
echo "  Chay lab:"
echo "    labtainer ${LAB}"
echo "========================================================"
