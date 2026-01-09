#!/bin/bash
# Create base VM images for malware sandbox analysis
# Supports both ARM64 (native on RPi5) and x64 (emulated)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="$SCRIPT_DIR"
AGENT_DIR="$SCRIPT_DIR/agent"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check dependencies
check_deps() {
    local deps=("qemu-img" "wget" "xz")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        log_info "Install with: sudo apt install qemu-utils wget xz-utils"
        exit 1
    fi
}

# Download Ubuntu cloud image
download_cloud_image() {
    local arch=$1
    local version="22.04"
    local base_url="https://cloud-images.ubuntu.com/releases/${version}/release"
    local img_name=""
    local output_name=""
    
    case $arch in
        arm64|aarch64)
            img_name="ubuntu-${version}-server-cloudimg-arm64.img"
            output_name="ubuntu-arm64-base.img"
            ;;
        x64|amd64|x86_64)
            img_name="ubuntu-${version}-server-cloudimg-amd64.img"
            output_name="ubuntu-x64-base.img"
            ;;
        *)
            log_error "Unknown architecture: $arch"
            exit 1
            ;;
    esac
    
    local output_path="$IMAGES_DIR/$output_name"
    
    if [ -f "$output_path" ]; then
        log_info "Base image already exists: $output_path"
        return 0
    fi
    
    log_info "Downloading Ubuntu $version cloud image for $arch..."
    wget -q --show-progress -O "$output_path" "$base_url/$img_name"
    
    log_info "Downloaded: $output_path"
}

# Create qcow2 image from base
create_qcow2() {
    local arch=$1
    local size=${2:-20G}
    local base_name=""
    local output_name=""
    
    case $arch in
        arm64|aarch64)
            base_name="ubuntu-arm64-base.img"
            output_name="ubuntu-arm64.qcow2"
            ;;
        x64|amd64|x86_64)
            base_name="ubuntu-x64-base.img"
            output_name="ubuntu-x64.qcow2"
            ;;
    esac
    
    local base_path="$IMAGES_DIR/$base_name"
    local output_path="$IMAGES_DIR/$output_name"
    
    if [ ! -f "$base_path" ]; then
        log_error "Base image not found: $base_path"
        exit 1
    fi
    
    log_info "Creating qcow2 image: $output_name (size: $size)"
    
    # Convert to qcow2 format
    qemu-img convert -f qcow2 -O qcow2 "$base_path" "$output_path"
    
    # Resize to specified size
    qemu-img resize "$output_path" "$size"
    
    log_info "Created: $output_path"
}

# Create cloud-init configuration
create_cloud_init() {
    local arch=$1
    local output_dir="$IMAGES_DIR/cloud-init-$arch"
    
    mkdir -p "$output_dir"
    
    # Meta-data
    cat > "$output_dir/meta-data" << EOF
instance-id: sandbox-$arch
local-hostname: sandbox
EOF

    # User-data with setup
    cat > "$output_dir/user-data" << 'EOF'
#cloud-config
hostname: sandbox
manage_etc_hosts: true

users:
  - name: sandbox
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    # Password: sandbox (hashed)
    passwd: $6$rounds=4096$sandbox$KhWj4Xj5B4Fq2N2h7Kz8vY6x5w4s3d2f1a0Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp

# Install required packages
packages:
  - python3
  - python3-pip
  - python3-venv
  - nodejs
  - npm
  - strace
  - ltrace
  - tcpdump
  - inotify-tools
  - curl
  - wget
  - git
  - build-essential
  - linux-tools-common

# Run commands
runcmd:
  # Create sandbox directories
  - mkdir -p /opt/sandbox
  - mkdir -p /opt/anti_vm
  - mkdir -p /tmp/analysis
  
  # Set permissions
  - chown -R sandbox:sandbox /opt/sandbox
  - chown -R sandbox:sandbox /tmp/analysis
  
  # Install Python packages for agent
  - pip3 install psutil watchdog pyinotify
  
  # Disable unnecessary services
  - systemctl disable snapd.service || true
  - systemctl disable snapd.socket || true
  - systemctl disable multipathd.service || true
  
  # Configure kernel parameters
  - sysctl -w kernel.randomize_va_space=0
  - sysctl -w kernel.dmesg_restrict=1
  
  # Clear logs
  - truncate -s 0 /var/log/syslog
  - truncate -s 0 /var/log/auth.log
  - journalctl --vacuum-time=1s
  
  # Signal ready
  - touch /tmp/cloud-init-complete

# Final message
final_message: "Sandbox VM ready after $UPTIME seconds"
EOF

    # Create cloud-init ISO
    if command -v genisoimage &> /dev/null; then
        genisoimage -output "$IMAGES_DIR/cloud-init-$arch.iso" \
            -volid cidata -joliet -rock \
            "$output_dir/user-data" "$output_dir/meta-data"
        log_info "Created cloud-init ISO: cloud-init-$arch.iso"
    elif command -v mkisofs &> /dev/null; then
        mkisofs -output "$IMAGES_DIR/cloud-init-$arch.iso" \
            -volid cidata -joliet -rock \
            "$output_dir/user-data" "$output_dir/meta-data"
        log_info "Created cloud-init ISO: cloud-init-$arch.iso"
    else
        log_warn "genisoimage/mkisofs not found, skipping ISO creation"
        log_info "Install with: sudo apt install genisoimage"
    fi
}

# Create empty disk image (alternative to cloud images)
create_empty_image() {
    local arch=$1
    local size=${2:-20G}
    local output_name="ubuntu-$arch.qcow2"
    local output_path="$IMAGES_DIR/$output_name"
    
    log_info "Creating empty qcow2 image: $output_name (size: $size)"
    qemu-img create -f qcow2 "$output_path" "$size"
    log_info "Created: $output_path"
    log_warn "You need to install OS manually using QEMU"
}

# Print usage
usage() {
    cat << EOF
Usage: $0 [command] [options]

Commands:
    download <arch>     Download Ubuntu cloud image (arm64|x64)
    create <arch>       Create qcow2 from cloud image
    cloud-init <arch>   Create cloud-init configuration
    empty <arch> [size] Create empty disk image
    all <arch>          Do all steps for architecture
    
Options:
    arm64, aarch64      ARM64 architecture (native on RPi5)
    x64, amd64, x86_64  x86-64 architecture (emulated on RPi5)
    
Examples:
    $0 all arm64        Create complete ARM64 image
    $0 all x64          Create complete x64 image
    $0 download arm64   Download ARM64 cloud image only
EOF
}

# Main
main() {
    check_deps
    
    case ${1:-help} in
        download)
            download_cloud_image "$2"
            ;;
        create)
            create_qcow2 "$2" "${3:-20G}"
            ;;
        cloud-init)
            create_cloud_init "$2"
            ;;
        empty)
            create_empty_image "$2" "${3:-20G}"
            ;;
        all)
            if [ -z "$2" ]; then
                log_error "Architecture required"
                usage
                exit 1
            fi
            download_cloud_image "$2"
            create_qcow2 "$2" "20G"
            create_cloud_init "$2"
            log_info "All done for $2!"
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
}

main "$@"
