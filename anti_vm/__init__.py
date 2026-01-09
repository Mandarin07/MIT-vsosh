"""
Anti-VM Detection Module

This module provides techniques to hide virtual machine artifacts
and make the sandbox environment appear like a real physical machine.
"""

from .cpuid_mask import CPUIDMasker, get_cpuid_args
from .smbios_spoof import SMBIOSSpoofer, get_smbios_args
from .hardware_spoof import HardwareSpoofer, get_hardware_args
from .timing_fix import TimingFixer, get_timing_args
from .sensors_fake import SensorsFaker
from .artifacts import ArtifactsGenerator
from .qemu_args import QEMUArgsBuilder, build_anti_vm_args

__all__ = [
    'CPUIDMasker',
    'SMBIOSSpoofer', 
    'HardwareSpoofer',
    'TimingFixer',
    'SensorsFaker',
    'ArtifactsGenerator',
    'QEMUArgsBuilder',
    'get_cpuid_args',
    'get_smbios_args',
    'get_hardware_args',
    'get_timing_args',
    'build_anti_vm_args',
]

__version__ = '1.0.0'
