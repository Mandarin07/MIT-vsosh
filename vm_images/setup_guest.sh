#!/bin/bash
# Guest VM Setup Script
# Run this inside the VM after initial boot to configure anti-VM and sandbox

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Create directory structure
setup_directories() {
    log_info "Creating directory structure..."
    
    sudo mkdir -p /opt/sandbox
    sudo mkdir -p /opt/anti_vm/fake_sysfs
    sudo mkdir -p /opt/anti_vm/fake_dmi
    sudo mkdir -p /opt/anti_vm/fake_proc
    sudo mkdir -p /tmp/analysis
    
    sudo chown -R $(whoami):$(whoami) /opt/sandbox
    sudo chown -R root:root /opt/anti_vm
}

# Install required packages
install_packages() {
    log_info "Installing required packages..."
    
    sudo apt-get update
    sudo apt-get install -y \
        python3 python3-pip python3-venv \
        strace ltrace \
        tcpdump \
        inotify-tools \
        sysstat \
        procps \
        net-tools \
        curl wget \
        jq \
        acl
    
    # Python packages for agent
    pip3 install --user psutil watchdog pyinotify
}

# Setup fake DMI/SMBIOS data
setup_fake_dmi() {
    log_info "Setting up fake DMI data..."
    
    local dmi_dir="/opt/anti_vm/fake_dmi"
    
    # BIOS Information
    echo "Dell Inc." | sudo tee "$dmi_dir/bios_vendor" > /dev/null
    echo "A12" | sudo tee "$dmi_dir/bios_version" > /dev/null
    echo "03/15/2023" | sudo tee "$dmi_dir/bios_date" > /dev/null
    
    # System Information  
    echo "Dell Inc." | sudo tee "$dmi_dir/sys_vendor" > /dev/null
    echo "OptiPlex 7080" | sudo tee "$dmi_dir/product_name" > /dev/null
    echo "1.0" | sudo tee "$dmi_dir/product_version" > /dev/null
    echo "ABC$(shuf -i 1000000-9999999 -n 1)" | sudo tee "$dmi_dir/product_serial" > /dev/null
    echo "$(uuidgen)" | sudo tee "$dmi_dir/product_uuid" > /dev/null
    
    # Board Information
    echo "Dell Inc." | sudo tee "$dmi_dir/board_vendor" > /dev/null
    echo "0X8DXD" | sudo tee "$dmi_dir/board_name" > /dev/null
    echo "A00" | sudo tee "$dmi_dir/board_version" > /dev/null
    echo ".XYZ$(shuf -i 1000000-9999999 -n 1)." | sudo tee "$dmi_dir/board_serial" > /dev/null
    
    # Chassis Information
    echo "Dell Inc." | sudo tee "$dmi_dir/chassis_vendor" > /dev/null
    echo "3" | sudo tee "$dmi_dir/chassis_type" > /dev/null
    echo "GHI$(shuf -i 100000-999999 -n 1)" | sudo tee "$dmi_dir/chassis_serial" > /dev/null
}

# Setup fake thermal/hardware sensors
setup_fake_sensors() {
    log_info "Setting up fake hardware sensors..."
    
    local sysfs_dir="/opt/anti_vm/fake_sysfs"
    
    # Thermal zone
    sudo mkdir -p "$sysfs_dir/class/thermal/thermal_zone0"
    echo "47000" | sudo tee "$sysfs_dir/class/thermal/thermal_zone0/temp" > /dev/null
    echo "x86_pkg_temp" | sudo tee "$sysfs_dir/class/thermal/thermal_zone0/type" > /dev/null
    echo "step_wise" | sudo tee "$sysfs_dir/class/thermal/thermal_zone0/policy" > /dev/null
    
    # Additional thermal zones
    sudo mkdir -p "$sysfs_dir/class/thermal/thermal_zone1"
    echo "42000" | sudo tee "$sysfs_dir/class/thermal/thermal_zone1/temp" > /dev/null
    echo "acpitz" | sudo tee "$sysfs_dir/class/thermal/thermal_zone1/type" > /dev/null
    
    # Hwmon (fans, temps)
    sudo mkdir -p "$sysfs_dir/class/hwmon/hwmon0"
    echo "coretemp" | sudo tee "$sysfs_dir/class/hwmon/hwmon0/name" > /dev/null
    echo "48000" | sudo tee "$sysfs_dir/class/hwmon/hwmon0/temp1_input" > /dev/null
    echo "Core 0" | sudo tee "$sysfs_dir/class/hwmon/hwmon0/temp1_label" > /dev/null
    echo "100000" | sudo tee "$sysfs_dir/class/hwmon/hwmon0/temp1_max" > /dev/null
    
    # Fan sensors
    sudo mkdir -p "$sysfs_dir/class/hwmon/hwmon1"
    echo "dell_smm" | sudo tee "$sysfs_dir/class/hwmon/hwmon1/name" > /dev/null
    echo "2400" | sudo tee "$sysfs_dir/class/hwmon/hwmon1/fan1_input" > /dev/null
    echo "CPU Fan" | sudo tee "$sysfs_dir/class/hwmon/hwmon1/fan1_label" > /dev/null
    echo "1800" | sudo tee "$sysfs_dir/class/hwmon/hwmon1/fan2_input" > /dev/null
    echo "System Fan" | sudo tee "$sysfs_dir/class/hwmon/hwmon1/fan2_label" > /dev/null
    
    # Battery (for laptop appearance)
    sudo mkdir -p "$sysfs_dir/class/power_supply/BAT0"
    echo "Discharging" | sudo tee "$sysfs_dir/class/power_supply/BAT0/status" > /dev/null
    echo "67" | sudo tee "$sysfs_dir/class/power_supply/BAT0/capacity" > /dev/null
    echo "Battery" | sudo tee "$sysfs_dir/class/power_supply/BAT0/type" > /dev/null
    echo "Dell" | sudo tee "$sysfs_dir/class/power_supply/BAT0/manufacturer" > /dev/null
    echo "DELL 7VTMR" | sudo tee "$sysfs_dir/class/power_supply/BAT0/model_name" > /dev/null
    echo "Li-ion" | sudo tee "$sysfs_dir/class/power_supply/BAT0/technology" > /dev/null
    echo "48000000" | sudo tee "$sysfs_dir/class/power_supply/BAT0/energy_full" > /dev/null
    echo "32160000" | sudo tee "$sysfs_dir/class/power_supply/BAT0/energy_now" > /dev/null
    
    # AC adapter
    sudo mkdir -p "$sysfs_dir/class/power_supply/AC"
    echo "Mains" | sudo tee "$sysfs_dir/class/power_supply/AC/type" > /dev/null
    echo "0" | sudo tee "$sysfs_dir/class/power_supply/AC/online" > /dev/null
}

# Setup fake /proc/cpuinfo
setup_fake_cpuinfo() {
    log_info "Setting up fake cpuinfo..."
    
    local proc_dir="/opt/anti_vm/fake_proc"
    
    # Create realistic cpuinfo (Intel i7)
    cat > "$proc_dir/cpuinfo" << 'EOF'
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 165
model name	: Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz
stepping	: 5
microcode	: 0xea
cpu MHz		: 2903.998
cache size	: 16384 KB
physical id	: 0
siblings	: 8
core id		: 0
cpu cores	: 8
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 22
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d arch_capabilities
vmx flags	: vnmi preemption_timer posted_intr invvpid ept_x_only ept_ad ept_1gb flexpriority apicv tsc_offset vtpr mtf vapic ept vpid unrestricted_guest vapic_reg vid ple shadow_vmcs pml ept_mode_based_exec tsc_scaling
bugs		: spectre_v1 spectre_v2 spec_store_bypass swapgs itlb_multihit srbds
bogomips	: 5799.77
clflush size	: 64
cache_alignment	: 64
address sizes	: 39 bits physical, 48 bits virtual
power management:

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 165
model name	: Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz
stepping	: 5
microcode	: 0xea
cpu MHz		: 2900.000
cache size	: 16384 KB
physical id	: 0
siblings	: 8
core id		: 1
cpu cores	: 8
apicid		: 2
initial apicid	: 2
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

    sudo chown root:root "$proc_dir/cpuinfo"
    sudo chmod 444 "$proc_dir/cpuinfo"
}

# Create anti-VM startup service
setup_antivm_service() {
    log_info "Setting up anti-VM service..."
    
    # Create the anti-vm script
    sudo tee /opt/anti_vm/setup.sh > /dev/null << 'EOF'
#!/bin/bash
# Anti-VM setup script - run at boot

# 1. Mount fake cpuinfo
if [ -f /opt/anti_vm/fake_proc/cpuinfo ]; then
    mount --bind /opt/anti_vm/fake_proc/cpuinfo /proc/cpuinfo 2>/dev/null || true
fi

# 2. Mount fake DMI
if [ -d /opt/anti_vm/fake_dmi ] && [ -d /sys/class/dmi/id ]; then
    for f in /opt/anti_vm/fake_dmi/*; do
        fname=$(basename "$f")
        if [ -f "/sys/class/dmi/id/$fname" ]; then
            mount --bind "$f" "/sys/class/dmi/id/$fname" 2>/dev/null || true
        fi
    done
fi

# 3. Clear dmesg
dmesg -C 2>/dev/null || true

# 4. Unload suspicious modules
rmmod virtio_balloon 2>/dev/null || true
rmmod virtio_console 2>/dev/null || true
rmmod qemu_fw_cfg 2>/dev/null || true

# 5. Hide QEMU/KVM from dmesg by restricting access
sysctl -w kernel.dmesg_restrict=1 2>/dev/null || true

# 6. Remove VM-related packages if present
dpkg -l | grep -q "open-vm-tools" && apt-get remove -y open-vm-tools 2>/dev/null || true
dpkg -l | grep -q "virtualbox-guest" && apt-get remove -y virtualbox-guest* 2>/dev/null || true

# 7. Update sensor values with some variance
update_sensors() {
    local base_temp=45
    local variance=$((RANDOM % 10))
    local temp=$((base_temp + variance))
    echo "${temp}000" > /opt/anti_vm/fake_sysfs/class/thermal/thermal_zone0/temp 2>/dev/null
    
    local fan_base=2200
    local fan_variance=$((RANDOM % 400))
    echo $((fan_base + fan_variance)) > /opt/anti_vm/fake_sysfs/class/hwmon/hwmon1/fan1_input 2>/dev/null
}
update_sensors

# 8. Start sensor update loop in background
(while true; do
    sleep 30
    update_sensors
done) &

echo "Anti-VM setup complete"
EOF

    sudo chmod +x /opt/anti_vm/setup.sh
    
    # Create systemd service
    sudo tee /etc/systemd/system/anti-vm.service > /dev/null << 'EOF'
[Unit]
Description=Anti-VM Detection Setup
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/anti_vm/setup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable anti-vm.service
}

# Setup sandbox agent service
setup_agent_service() {
    log_info "Setting up sandbox agent service..."
    
    sudo tee /etc/systemd/system/sandbox-agent.service > /dev/null << 'EOF'
[Unit]
Description=Sandbox Analysis Agent
After=network.target anti-vm.service

[Service]
Type=simple
User=sandbox
WorkingDirectory=/opt/sandbox
ExecStart=/usr/bin/python3 /opt/sandbox/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable sandbox-agent.service
}

# Create clean snapshot preparation script
create_snapshot_prep() {
    log_info "Creating snapshot preparation script..."
    
    sudo tee /opt/sandbox/prepare_snapshot.sh > /dev/null << 'EOF'
#!/bin/bash
# Run this before creating a clean snapshot

# Clear logs
sudo truncate -s 0 /var/log/syslog
sudo truncate -s 0 /var/log/auth.log
sudo truncate -s 0 /var/log/kern.log
sudo journalctl --vacuum-time=1s

# Clear bash history
history -c
cat /dev/null > ~/.bash_history

# Clear temp files
sudo rm -rf /tmp/*
sudo rm -rf /var/tmp/*

# Sync filesystem
sync

echo "Ready for snapshot"
EOF

    sudo chmod +x /opt/sandbox/prepare_snapshot.sh
}

# Main setup function
main() {
    log_info "Starting guest VM setup..."
    
    setup_directories
    install_packages
    setup_fake_dmi
    setup_fake_sensors
    setup_fake_cpuinfo
    setup_antivm_service
    setup_agent_service
    create_snapshot_prep
    
    log_info "Guest setup complete!"
    log_info "Next steps:"
    log_info "  1. Copy agent.py to /opt/sandbox/"
    log_info "  2. Run /opt/sandbox/prepare_snapshot.sh"
    log_info "  3. Create a 'clean' snapshot from host"
}

main "$@"
