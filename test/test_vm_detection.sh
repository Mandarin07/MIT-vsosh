#!/bin/bash
# VM Detection Test Script
# Run this inside the guest VM to verify anti-VM measures are working

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "[INFO] $1"; }

echo "=============================================="
echo "        VM Detection Test Suite              "
echo "=============================================="
echo ""

PASS_COUNT=0
FAIL_COUNT=0

# Test 1: Check /proc/cpuinfo for hypervisor flag
test_cpuinfo() {
    info "Checking /proc/cpuinfo for hypervisor flag..."
    if grep -qi "hypervisor" /proc/cpuinfo 2>/dev/null; then
        fail "Hypervisor flag found in /proc/cpuinfo"
        ((FAIL_COUNT++))
    else
        pass "No hypervisor flag in /proc/cpuinfo"
        ((PASS_COUNT++))
    fi
}

# Test 2: Check DMI/SMBIOS for VM indicators
test_dmi() {
    info "Checking DMI/SMBIOS for VM indicators..."
    
    local vm_found=0
    local vm_strings="QEMU|VirtualBox|VMware|Xen|KVM|Hyper-V|Virtual|Bochs|innotek"
    
    # Check dmidecode if available
    if command -v dmidecode &> /dev/null; then
        if sudo dmidecode 2>/dev/null | grep -qiE "$vm_strings"; then
            fail "VM indicator found in dmidecode output"
            vm_found=1
        fi
    fi
    
    # Check /sys/class/dmi/id/
    if [ -d /sys/class/dmi/id ]; then
        for f in /sys/class/dmi/id/*; do
            if [ -r "$f" ] && grep -qiE "$vm_strings" "$f" 2>/dev/null; then
                fail "VM indicator found in $f: $(cat $f)"
                vm_found=1
            fi
        done
    fi
    
    if [ $vm_found -eq 0 ]; then
        pass "No VM indicators in DMI/SMBIOS"
        ((PASS_COUNT++))
    else
        ((FAIL_COUNT++))
    fi
}

# Test 3: Check MAC address OUI
test_mac() {
    info "Checking network MAC address..."
    
    local vm_macs="52:54:00|00:0C:29|00:50:56|08:00:27|00:16:3E|00:15:5D"
    local mac_found=0
    
    for iface in /sys/class/net/*; do
        if [ -f "$iface/address" ]; then
            mac=$(cat "$iface/address" 2>/dev/null)
            if echo "$mac" | grep -qiE "^($vm_macs)"; then
                fail "VM MAC prefix detected: $mac"
                mac_found=1
            fi
        fi
    done
    
    if [ $mac_found -eq 0 ]; then
        pass "No VM MAC prefixes found"
        ((PASS_COUNT++))
    else
        ((FAIL_COUNT++))
    fi
}

# Test 4: Check for VM kernel modules
test_modules() {
    info "Checking for VM kernel modules..."
    
    local vm_modules="vboxguest|vboxsf|vmw_balloon|vmw_vmci|virtio_balloon|virtio_console|xen_|hyperv_"
    
    if lsmod 2>/dev/null | grep -qiE "$vm_modules"; then
        fail "VM kernel modules loaded"
        ((FAIL_COUNT++))
    else
        pass "No VM kernel modules loaded"
        ((PASS_COUNT++))
    fi
}

# Test 5: Check dmesg for VM indicators
test_dmesg() {
    info "Checking dmesg for VM indicators..."
    
    local vm_strings="QEMU|VirtualBox|VMware|Xen|KVM|Hyper-V|Virtual Machine"
    
    # Check if dmesg is accessible
    if dmesg 2>/dev/null | grep -qiE "$vm_strings"; then
        warn "VM indicator found in dmesg (may be restricted)"
        ((FAIL_COUNT++))
    else
        pass "No VM indicators in dmesg"
        ((PASS_COUNT++))
    fi
}

# Test 6: Check for VM-specific files/directories
test_files() {
    info "Checking for VM-specific files..."
    
    local fail_found=0
    local vm_files=(
        "/sys/hypervisor/type"
        "/proc/xen"
        "/proc/vz"
        "/dev/vboxguest"
        "/dev/vboxuser"
        "/.dockerenv"
    )
    
    for f in "${vm_files[@]}"; do
        if [ -e "$f" ]; then
            fail "VM file found: $f"
            fail_found=1
        fi
    done
    
    if [ $fail_found -eq 0 ]; then
        pass "No VM-specific files found"
        ((PASS_COUNT++))
    else
        ((FAIL_COUNT++))
    fi
}

# Test 7: Check for VM-specific processes
test_processes() {
    info "Checking for VM-specific processes..."
    
    local vm_procs="VBoxService|vmtoolsd|qemu-ga|spice-vdagent|xe-daemon"
    
    if pgrep -f "$vm_procs" &>/dev/null; then
        fail "VM process found running"
        ((FAIL_COUNT++))
    else
        pass "No VM processes running"
        ((PASS_COUNT++))
    fi
}

# Test 8: Check thermal sensors
test_thermal() {
    info "Checking thermal sensors..."
    
    if [ -d /sys/class/thermal/thermal_zone0 ]; then
        temp=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null)
        if [ -n "$temp" ] && [ "$temp" -gt 30000 ] && [ "$temp" -lt 90000 ]; then
            pass "Thermal sensor present with reasonable value: $((temp/1000))°C"
            ((PASS_COUNT++))
        else
            warn "Thermal sensor value unusual: $temp"
        fi
    else
        warn "No thermal sensors found"
    fi
}

# Test 9: Check fan sensors
test_fans() {
    info "Checking fan sensors..."
    
    local fan_found=0
    for hwmon in /sys/class/hwmon/hwmon*; do
        if [ -f "$hwmon/fan1_input" ]; then
            rpm=$(cat "$hwmon/fan1_input" 2>/dev/null)
            if [ -n "$rpm" ] && [ "$rpm" -gt 500 ] && [ "$rpm" -lt 10000 ]; then
                pass "Fan sensor present with reasonable RPM: $rpm"
                fan_found=1
                ((PASS_COUNT++))
                break
            fi
        fi
    done
    
    if [ $fan_found -eq 0 ]; then
        warn "No fan sensors found"
    fi
}

# Test 10: Check disk serial
test_disk_serial() {
    info "Checking disk serial numbers..."
    
    local vm_serials="QM00001|VBOX|VMWARE|QEMU"
    local fail_found=0
    
    for disk in /dev/sd? /dev/vd? /dev/nvme?n1; do
        if [ -b "$disk" ]; then
            serial=$(udevadm info --query=all --name="$disk" 2>/dev/null | grep ID_SERIAL= | cut -d= -f2)
            if [ -n "$serial" ]; then
                if echo "$serial" | grep -qiE "$vm_serials"; then
                    fail "VM disk serial detected: $serial"
                    fail_found=1
                else
                    info "Disk serial: $serial"
                fi
            fi
        fi
    done 2>/dev/null
    
    if [ $fail_found -eq 0 ]; then
        pass "No VM disk serials found"
        ((PASS_COUNT++))
    else
        ((FAIL_COUNT++))
    fi
}

# Test 11: CPUID check (x86 only)
test_cpuid() {
    if [ "$(uname -m)" != "x86_64" ] && [ "$(uname -m)" != "i686" ]; then
        info "Skipping CPUID test (not x86)"
        return
    fi
    
    info "Checking CPUID for hypervisor presence..."
    
    # Try to use cpuid tool if available
    if command -v cpuid &> /dev/null; then
        if cpuid 2>/dev/null | grep -qi "hypervisor"; then
            fail "Hypervisor detected via CPUID"
            ((FAIL_COUNT++))
        else
            pass "No hypervisor in CPUID"
            ((PASS_COUNT++))
        fi
    else
        warn "cpuid tool not available"
    fi
}

# Test 12: Check for user artifacts
test_artifacts() {
    info "Checking for user artifacts..."
    
    local home="${HOME:-/home/user}"
    local artifact_count=0
    
    [ -d "$home/Documents" ] && ((artifact_count++))
    [ -d "$home/Downloads" ] && ((artifact_count++))
    [ -d "$home/Pictures" ] && ((artifact_count++))
    [ -f "$home/.bash_history" ] && ((artifact_count++))
    
    # Check browser history
    [ -f "$home/.config/chromium/Default/History" ] && ((artifact_count++))
    [ -f "$home/.config/google-chrome/Default/History" ] && ((artifact_count++))
    
    if [ $artifact_count -ge 3 ]; then
        pass "User artifacts present ($artifact_count found)"
        ((PASS_COUNT++))
    else
        warn "Few user artifacts found ($artifact_count)"
    fi
}

# Run all tests
echo ""
test_cpuinfo
test_dmi
test_mac
test_modules
test_dmesg
test_files
test_processes
test_thermal
test_fans
test_disk_serial
test_cpuid
test_artifacts

# Summary
echo ""
echo "=============================================="
echo "                 SUMMARY                      "
echo "=============================================="
echo -e "${GREEN}Passed: $PASS_COUNT${NC}"
echo -e "${RED}Failed: $FAIL_COUNT${NC}"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}All tests passed! VM is well hidden.${NC}"
    exit 0
else
    echo -e "${YELLOW}Some tests failed. Review and fix the issues above.${NC}"
    exit 1
fi
