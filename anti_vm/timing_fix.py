"""
Timing-Based Detection Countermeasures

Malware uses timing-based techniques to detect virtual environments:
- RDTSC instruction timing variations
- Sleep timing discrepancies
- Instruction timing differences between VM and real hardware
- TSC (Time Stamp Counter) inconsistencies

This module provides QEMU configuration to stabilize timing behavior.
"""

from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class TimingConfig:
    """Timing stabilization configuration"""
    
    # TSC (Time Stamp Counter) settings
    enable_invtsc: bool = True  # Invariant TSC
    tsc_frequency: int = 3600000000  # 3.6 GHz
    tsc_scaling: bool = False  # Disable TSC scaling
    
    # Clock settings
    clock_source: str = "host"  # host, rt, vm
    
    # HPET (High Precision Event Timer)
    disable_hpet: bool = True  # HPET can be used for timing detection
    
    # KVM specific
    kvmclock: bool = False  # Disable KVM paravirt clock
    
    # Instruction timing
    stabilize_instructions: bool = True


class TimingFixer:
    """
    Generates QEMU arguments to stabilize timing and defeat timing-based detection.
    
    Timing-based detection works by:
    1. Measuring RDTSC before/after VM-detectable operations
    2. Comparing timing ratios between different operations
    3. Looking for timing anomalies in sleep/delay functions
    4. Checking TSC frequency and stability
    
    This class configures QEMU to minimize these differences.
    """
    
    def __init__(self, config: Optional[TimingConfig] = None):
        self.config = config or TimingConfig()
    
    def get_cpu_timing_flags(self) -> List[str]:
        """
        Get CPU flags related to timing.
        
        Returns list of feature flags to add to -cpu argument.
        """
        flags = []
        
        # Invariant TSC - makes TSC more consistent
        if self.config.enable_invtsc:
            flags.append('+invtsc')
        
        # Set TSC frequency for consistency
        if self.config.tsc_frequency:
            flags.append(f'tsc-frequency={self.config.tsc_frequency}')
        
        # Disable KVM clock if hiding VM
        if not self.config.kvmclock:
            flags.append('-kvmclock')
            flags.append('-kvmclock-stable-bit')
        
        return flags
    
    def get_machine_timing_flags(self) -> List[str]:
        """
        Get machine flags related to timing.
        
        Returns list to add to -machine argument.
        """
        flags = []
        
        # Disable HPET
        if self.config.disable_hpet:
            flags.append('hpet=off')
        
        return flags
    
    def get_rtc_args(self) -> List[str]:
        """
        Get RTC (Real Time Clock) arguments.
        
        The RTC configuration affects time-keeping behavior.
        """
        args = []
        
        # Use host clock for better accuracy
        if self.config.clock_source == "host":
            args.extend(['-rtc', 'base=utc,clock=host,driftfix=slew'])
        else:
            args.extend(['-rtc', 'base=utc,clock=vm'])
        
        return args
    
    def get_global_timing_args(self) -> List[str]:
        """
        Get global QEMU arguments for timing.
        
        These affect overall timing behavior of the emulation.
        """
        args = []
        
        # Disable various timing-related features that can be detected
        # These are added as -global options
        
        # Disable KVMCLOCK device
        if not self.config.kvmclock:
            args.extend(['-global', 'kvm-pit.lost_tick_policy=delay'])
        
        return args
    
    def get_all_timing_args(self) -> List[str]:
        """Get all timing-related arguments"""
        args = []
        args.extend(self.get_rtc_args())
        args.extend(self.get_global_timing_args())
        return args
    
    def get_cpu_flags_string(self) -> str:
        """Get CPU timing flags as a comma-separated string"""
        flags = self.get_cpu_timing_flags()
        return ','.join(flags) if flags else ''


# Additional timing-based detection countermeasures for inside the guest

GUEST_TIMING_SCRIPT = '''#!/bin/bash
# Guest-side timing stabilization script

# Disable kernel's handling of TSC issues
if [ -f /sys/devices/system/clocksource/clocksource0/current_clocksource ]; then
    # Use TSC as clocksource if available and stable
    available=$(cat /sys/devices/system/clocksource/clocksource0/available_clocksource)
    if echo "$available" | grep -q "tsc"; then
        echo tsc > /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || true
    fi
fi

# Disable TSC watchdog if it exists
if [ -f /sys/module/tsc/parameters/allow_unstable_tsc ]; then
    echo 1 > /sys/module/tsc/parameters/allow_unstable_tsc 2>/dev/null || true
fi

# Set CPU frequency scaling to performance (reduces timing variations)
for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    if [ -f "$gov" ]; then
        echo performance > "$gov" 2>/dev/null || true
    fi
done

# Disable frequency boost (can cause timing variations)
if [ -f /sys/devices/system/cpu/cpufreq/boost ]; then
    echo 0 > /sys/devices/system/cpu/cpufreq/boost 2>/dev/null || true
fi

echo "Guest timing stabilization complete"
'''


def get_timing_args(stabilize: bool = True, 
                   tsc_frequency: int = 3600000000) -> List[str]:
    """
    Convenience function to get timing-related QEMU arguments.
    
    Args:
        stabilize: Whether to apply timing stabilization
        tsc_frequency: TSC frequency in Hz
        
    Returns:
        List of QEMU arguments
    """
    if not stabilize:
        return []
    
    config = TimingConfig(
        enable_invtsc=True,
        tsc_frequency=tsc_frequency,
        disable_hpet=True,
        kvmclock=False,
    )
    
    fixer = TimingFixer(config)
    return fixer.get_all_timing_args()


def get_timing_cpu_flags(stabilize: bool = True,
                        tsc_frequency: int = 3600000000) -> List[str]:
    """
    Get CPU flags for timing stabilization.
    
    These should be added to the -cpu argument.
    
    Args:
        stabilize: Whether to apply timing stabilization
        tsc_frequency: TSC frequency in Hz
        
    Returns:
        List of CPU flags
    """
    if not stabilize:
        return []
    
    config = TimingConfig(
        enable_invtsc=True,
        tsc_frequency=tsc_frequency,
        kvmclock=False,
    )
    
    fixer = TimingFixer(config)
    return fixer.get_cpu_timing_flags()
