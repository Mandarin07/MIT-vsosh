#!/bin/bash
# Complete Anti-VM Setup Script for Guest System
# This script should be run inside the VM to configure all anti-detection measures

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }
log_step() { echo -e "${GREEN}[STEP]${NC} $1"; }

ANTI_VM_DIR="/opt/anti_vm"

# ============================================================
# STEP 1: Create Directory Structure
# ============================================================
setup_directories() {
    log_step "Creating directory structure..."
    
    sudo mkdir -p "$ANTI_VM_DIR"/{fake_sysfs,fake_dmi,fake_proc,scripts}
    sudo mkdir -p "$ANTI_VM_DIR/fake_sysfs/class"/{thermal,hwmon,power_supply}
    sudo mkdir -p "$ANTI_VM_DIR/fake_sysfs/devices/virtual/input"
    sudo mkdir -p /opt/sandbox
    
    sudo chmod 755 "$ANTI_VM_DIR"
}

# ============================================================
# STEP 2: Create Fake DMI/SMBIOS Data
# ============================================================
setup_fake_dmi() {
    log_step "Setting up fake DMI data..."
    
    local dmi_dir="$ANTI_VM_DIR/fake_dmi"
    
    # Generate random serials
    local sys_serial="$(cat /dev/urandom | tr -dc 'A-Z0-9' | head -c7)"
    local board_serial=".$(cat /dev/urandom | tr -dc 'A-Z0-9' | head -c10)."
    local chassis_serial="$sys_serial"
    local uuid="$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)"
    
    # BIOS Information
    echo "Dell Inc." | sudo tee "$dmi_dir/bios_vendor" > /dev/null
    echo "A12" | sudo tee "$dmi_dir/bios_version" > /dev/null
    echo "03/15/2023" | sudo tee "$dmi_dir/bios_date" > /dev/null
    
    # System Information
    echo "Dell Inc." | sudo tee "$dmi_dir/sys_vendor" > /dev/null
    echo "OptiPlex 7080" | sudo tee "$dmi_dir/product_name" > /dev/null
    echo "1.0" | sudo tee "$dmi_dir/product_version" > /dev/null
    echo "$sys_serial" | sudo tee "$dmi_dir/product_serial" > /dev/null
    echo "$uuid" | sudo tee "$dmi_dir/product_uuid" > /dev/null
    echo "Desktop" | sudo tee "$dmi_dir/product_sku" > /dev/null
    echo "OptiPlex" | sudo tee "$dmi_dir/product_family" > /dev/null
    
    # Board Information
    echo "Dell Inc." | sudo tee "$dmi_dir/board_vendor" > /dev/null
    echo "0X8DXD" | sudo tee "$dmi_dir/board_name" > /dev/null
    echo "A00" | sudo tee "$dmi_dir/board_version" > /dev/null
    echo "$board_serial" | sudo tee "$dmi_dir/board_serial" > /dev/null
    echo "" | sudo tee "$dmi_dir/board_asset_tag" > /dev/null
    
    # Chassis Information
    echo "Dell Inc." | sudo tee "$dmi_dir/chassis_vendor" > /dev/null
    echo "3" | sudo tee "$dmi_dir/chassis_type" > /dev/null
    echo "$chassis_serial" | sudo tee "$dmi_dir/chassis_serial" > /dev/null
    echo "" | sudo tee "$dmi_dir/chassis_asset_tag" > /dev/null
    
    log_info "DMI data created with serial: $sys_serial"
}

# ============================================================
# STEP 3: Create Fake CPU Info
# ============================================================
setup_fake_cpuinfo() {
    log_step "Setting up fake /proc/cpuinfo..."
    
    local cpuinfo="$ANTI_VM_DIR/fake_proc/cpuinfo"
    
    # Number of cores to emulate
    local num_cores=8
    
    cat > "$cpuinfo" << 'CPUINFO_END'
CPUINFO_END

    for ((i=0; i<num_cores; i++)); do
        cat >> "$cpuinfo" << EOF
processor	: $i
vendor_id	: GenuineIntel
cpu family	: 6
model		: 165
model name	: Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz
stepping	: 5
microcode	: 0xea
cpu MHz		: $((2900 + RANDOM % 100)).$((RANDOM % 1000))
cache size	: 16384 KB
physical id	: 0
siblings	: $num_cores
core id		: $i
cpu cores	: $num_cores
apicid		: $((i * 2))
initial apicid	: $((i * 2))
fpu		: yes
fpu_exception	: yes
cpuid level	: 22
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d arch_capabilities
bugs		: spectre_v1 spectre_v2 spec_store_bypass swapgs itlb_multihit srbds
bogomips	: 5799.77
clflush size	: 64
cache_alignment	: 64
address sizes	: 39 bits physical, 48 bits virtual
power management:

EOF
    done
    
    sudo chown root:root "$cpuinfo"
    sudo chmod 444 "$cpuinfo"
    
    log_info "Created cpuinfo with $num_cores cores"
}

# ============================================================
# STEP 4: Create Fake Thermal Sensors
# ============================================================
setup_fake_thermal() {
    log_step "Setting up fake thermal sensors..."
    
    local sysfs="$ANTI_VM_DIR/fake_sysfs"
    
    # Thermal zone 0 - CPU package
    sudo mkdir -p "$sysfs/class/thermal/thermal_zone0"
    echo "$((45000 + RANDOM % 10000))" | sudo tee "$sysfs/class/thermal/thermal_zone0/temp" > /dev/null
    echo "x86_pkg_temp" | sudo tee "$sysfs/class/thermal/thermal_zone0/type" > /dev/null
    echo "step_wise" | sudo tee "$sysfs/class/thermal/thermal_zone0/policy" > /dev/null
    echo "enabled" | sudo tee "$sysfs/class/thermal/thermal_zone0/mode" > /dev/null
    
    # Trip points
    echo "60000" | sudo tee "$sysfs/class/thermal/thermal_zone0/trip_point_0_temp" > /dev/null
    echo "passive" | sudo tee "$sysfs/class/thermal/thermal_zone0/trip_point_0_type" > /dev/null
    echo "80000" | sudo tee "$sysfs/class/thermal/thermal_zone0/trip_point_1_temp" > /dev/null
    echo "active" | sudo tee "$sysfs/class/thermal/thermal_zone0/trip_point_1_type" > /dev/null
    echo "100000" | sudo tee "$sysfs/class/thermal/thermal_zone0/trip_point_2_temp" > /dev/null
    echo "critical" | sudo tee "$sysfs/class/thermal/thermal_zone0/trip_point_2_type" > /dev/null
    
    # Thermal zone 1 - ACPI
    sudo mkdir -p "$sysfs/class/thermal/thermal_zone1"
    echo "$((40000 + RANDOM % 8000))" | sudo tee "$sysfs/class/thermal/thermal_zone1/temp" > /dev/null
    echo "acpitz" | sudo tee "$sysfs/class/thermal/thermal_zone1/type" > /dev/null
    echo "step_wise" | sudo tee "$sysfs/class/thermal/thermal_zone1/policy" > /dev/null
    
    log_info "Created thermal zones"
}

# ============================================================
# STEP 5: Create Fake Hwmon (Fans, Temps, Voltages)
# ============================================================
setup_fake_hwmon() {
    log_step "Setting up fake hwmon sensors..."
    
    local sysfs="$ANTI_VM_DIR/fake_sysfs"
    
    # hwmon0 - coretemp (CPU temperatures)
    sudo mkdir -p "$sysfs/class/hwmon/hwmon0"
    echo "coretemp" | sudo tee "$sysfs/class/hwmon/hwmon0/name" > /dev/null
    
    for i in {1..8}; do
        local temp=$((45000 + RANDOM % 15000))
        echo "$temp" | sudo tee "$sysfs/class/hwmon/hwmon0/temp${i}_input" > /dev/null
        echo "Core $((i-1))" | sudo tee "$sysfs/class/hwmon/hwmon0/temp${i}_label" > /dev/null
        echo "100000" | sudo tee "$sysfs/class/hwmon/hwmon0/temp${i}_max" > /dev/null
        echo "105000" | sudo tee "$sysfs/class/hwmon/hwmon0/temp${i}_crit" > /dev/null
    done
    
    # hwmon1 - dell_smm (Fan control)
    sudo mkdir -p "$sysfs/class/hwmon/hwmon1"
    echo "dell_smm" | sudo tee "$sysfs/class/hwmon/hwmon1/name" > /dev/null
    
    echo "$((2000 + RANDOM % 800))" | sudo tee "$sysfs/class/hwmon/hwmon1/fan1_input" > /dev/null
    echo "CPU Fan" | sudo tee "$sysfs/class/hwmon/hwmon1/fan1_label" > /dev/null
    echo "5000" | sudo tee "$sysfs/class/hwmon/hwmon1/fan1_max" > /dev/null
    
    echo "$((1500 + RANDOM % 600))" | sudo tee "$sysfs/class/hwmon/hwmon1/fan2_input" > /dev/null
    echo "System Fan" | sudo tee "$sysfs/class/hwmon/hwmon1/fan2_label" > /dev/null
    echo "4000" | sudo tee "$sysfs/class/hwmon/hwmon1/fan2_max" > /dev/null
    
    # hwmon2 - nct6775 (Motherboard sensors)
    sudo mkdir -p "$sysfs/class/hwmon/hwmon2"
    echo "nct6775" | sudo tee "$sysfs/class/hwmon/hwmon2/name" > /dev/null
    
    # Voltages
    echo "1104" | sudo tee "$sysfs/class/hwmon/hwmon2/in0_input" > /dev/null
    echo "Vcore" | sudo tee "$sysfs/class/hwmon/hwmon2/in0_label" > /dev/null
    echo "3312" | sudo tee "$sysfs/class/hwmon/hwmon2/in1_input" > /dev/null
    echo "+3.3V" | sudo tee "$sysfs/class/hwmon/hwmon2/in1_label" > /dev/null
    echo "5016" | sudo tee "$sysfs/class/hwmon/hwmon2/in2_input" > /dev/null
    echo "+5V" | sudo tee "$sysfs/class/hwmon/hwmon2/in2_label" > /dev/null
    echo "12048" | sudo tee "$sysfs/class/hwmon/hwmon2/in3_input" > /dev/null
    echo "+12V" | sudo tee "$sysfs/class/hwmon/hwmon2/in3_label" > /dev/null
    
    log_info "Created hwmon sensors"
}

# ============================================================
# STEP 6: Create Fake Battery (Optional - for laptop appearance)
# ============================================================
setup_fake_battery() {
    log_step "Setting up fake power supply..."
    
    local sysfs="$ANTI_VM_DIR/fake_sysfs"
    
    # AC adapter
    sudo mkdir -p "$sysfs/class/power_supply/AC"
    echo "Mains" | sudo tee "$sysfs/class/power_supply/AC/type" > /dev/null
    echo "1" | sudo tee "$sysfs/class/power_supply/AC/online" > /dev/null
    
    log_info "Created power supply"
}

# ============================================================
# STEP 7: Create Input Devices
# ============================================================
setup_fake_input() {
    log_step "Setting up fake input devices..."
    
    local input_dir="$ANTI_VM_DIR/fake_sysfs/devices/virtual/input"
    
    # Keyboard
    sudo mkdir -p "$input_dir/input0"
    echo "AT Translated Set 2 keyboard" | sudo tee "$input_dir/input0/name" > /dev/null
    echo "isa0060/serio0/input0" | sudo tee "$input_dir/input0/phys" > /dev/null
    
    # Mouse
    sudo mkdir -p "$input_dir/input1"
    echo "Logitech USB Receiver" | sudo tee "$input_dir/input1/name" > /dev/null
    echo "usb-0000:00:14.0-1/input0" | sudo tee "$input_dir/input1/phys" > /dev/null
    
    sudo touch "$input_dir/mice"
    
    log_info "Created input devices"
}

# ============================================================
# STEP 8: Create Boot-time Anti-VM Script
# ============================================================
create_antivm_script() {
    log_step "Creating anti-VM boot script..."
    
    sudo tee "$ANTI_VM_DIR/scripts/antivm_boot.sh" > /dev/null << 'SCRIPT_END'
#!/bin/bash
# Anti-VM Setup - Run at boot

ANTI_VM_DIR="/opt/anti_vm"

# Mount fake cpuinfo
if [ -f "$ANTI_VM_DIR/fake_proc/cpuinfo" ]; then
    mount --bind "$ANTI_VM_DIR/fake_proc/cpuinfo" /proc/cpuinfo 2>/dev/null
fi

# Mount fake DMI
if [ -d "$ANTI_VM_DIR/fake_dmi" ] && [ -d /sys/class/dmi/id ]; then
    for f in "$ANTI_VM_DIR/fake_dmi"/*; do
        [ -f "$f" ] || continue
        fname=$(basename "$f")
        target="/sys/class/dmi/id/$fname"
        [ -f "$target" ] && mount --bind "$f" "$target" 2>/dev/null
    done
fi

# Clear dmesg to hide boot messages
dmesg -C 2>/dev/null

# Restrict dmesg access
sysctl -w kernel.dmesg_restrict=1 2>/dev/null

# Unload VM-related modules
for mod in virtio_balloon virtio_console qemu_fw_cfg vboxguest vboxsf vmw_balloon vmw_vmci; do
    rmmod "$mod" 2>/dev/null
done

# Hide VM-related processes
# (These shouldn't exist in our setup, but just in case)
pkill -9 qemu-ga 2>/dev/null
pkill -9 spice-vdagent 2>/dev/null

# Update sensor values
update_sensors() {
    local base_temp=$((45 + RANDOM % 10))
    echo "${base_temp}000" > "$ANTI_VM_DIR/fake_sysfs/class/thermal/thermal_zone0/temp" 2>/dev/null
    
    local fan_rpm=$((2200 + RANDOM % 400))
    echo "$fan_rpm" > "$ANTI_VM_DIR/fake_sysfs/class/hwmon/hwmon1/fan1_input" 2>/dev/null
}
update_sensors

# Start sensor update daemon
(while true; do
    sleep 30
    update_sensors
done) &

logger "Anti-VM setup complete"
SCRIPT_END

    sudo chmod +x "$ANTI_VM_DIR/scripts/antivm_boot.sh"
    log_info "Created anti-VM boot script"
}

# ============================================================
# STEP 9: Create Systemd Service
# ============================================================
create_systemd_service() {
    log_step "Creating systemd service..."
    
    sudo tee /etc/systemd/system/anti-vm.service > /dev/null << 'SERVICE_END'
[Unit]
Description=Anti-VM Detection Setup
DefaultDependencies=no
Before=basic.target
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/opt/anti_vm/scripts/antivm_boot.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=basic.target
SERVICE_END

    sudo systemctl daemon-reload
    sudo systemctl enable anti-vm.service
    
    log_info "Created and enabled anti-vm service"
}

# ============================================================
# STEP 10: Clean Up VM Artifacts
# ============================================================
cleanup_vm_artifacts() {
    log_step "Cleaning up VM artifacts..."
    
    # Remove VM-related packages if present
    for pkg in open-vm-tools virtualbox-guest-utils qemu-guest-agent spice-vdagent; do
        if dpkg -l | grep -q "^ii.*$pkg"; then
            log_info "Removing $pkg..."
            sudo apt-get remove -y "$pkg" 2>/dev/null || true
        fi
    done
    
    # Remove VM-related files
    sudo rm -f /etc/vmware-tools/locations 2>/dev/null
    sudo rm -rf /etc/vmware-tools 2>/dev/null
    sudo rm -f /usr/bin/VBoxClient* 2>/dev/null
    sudo rm -f /usr/bin/VBoxControl 2>/dev/null
    
    # Clear logs
    sudo truncate -s 0 /var/log/syslog 2>/dev/null
    sudo truncate -s 0 /var/log/messages 2>/dev/null
    sudo truncate -s 0 /var/log/auth.log 2>/dev/null
    sudo truncate -s 0 /var/log/kern.log 2>/dev/null
    sudo journalctl --vacuum-time=1s 2>/dev/null
    
    log_info "Cleanup complete"
}

# ============================================================
# Main Execution
# ============================================================
main() {
    log_info "Starting Anti-VM setup for guest system..."
    echo ""
    
    setup_directories
    setup_fake_dmi
    setup_fake_cpuinfo
    setup_fake_thermal
    setup_fake_hwmon
    setup_fake_battery
    setup_fake_input
    create_antivm_script
    create_systemd_service
    cleanup_vm_artifacts
    
    echo ""
    log_info "========================================="
    log_info "Anti-VM setup complete!"
    log_info "========================================="
    log_info ""
    log_info "Next steps:"
    log_info "1. Copy sandbox agent to /opt/sandbox/"
    log_info "2. Run: sudo systemctl start anti-vm"
    log_info "3. Run: /opt/sandbox/prepare_snapshot.sh"
    log_info "4. Create a 'clean' snapshot from host"
}

main "$@"
