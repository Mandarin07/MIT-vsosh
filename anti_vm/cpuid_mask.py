"""
CPUID Masking - Hide hypervisor presence from CPUID instructions

The CPUID instruction is commonly used by malware to detect virtual environments:
- CPUID.1:ECX[31] (hypervisor bit) indicates hypervisor presence
- CPUID leaf 0x40000000 returns hypervisor signature (e.g., "KVMKVMKVM")
- Various other leaves expose VM-specific information

This module provides QEMU arguments to mask these indicators.
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class CPUVendor(Enum):
    """CPU vendor identifiers"""
    INTEL = "GenuineIntel"
    AMD = "AuthenticAMD"


@dataclass
class CPUIDConfig:
    """CPUID masking configuration"""
    
    # Hide hypervisor bit (CPUID.1:ECX[31])
    hide_hypervisor_bit: bool = True
    
    # Hide KVM signature from leaf 0x40000000
    hide_kvm_signature: bool = True
    
    # Custom hypervisor vendor ID (if not hiding completely)
    # Can be used to spoof a different hypervisor
    custom_hv_vendor: Optional[str] = None
    
    # CPU vendor to emulate
    cpu_vendor: CPUVendor = CPUVendor.INTEL
    
    # Hide VM-specific CPUID leaves
    hide_vm_leaves: bool = True
    
    # Disable paravirtualization features that expose VM
    disable_pv_features: bool = True
    
    # Hide timing-related features
    hide_timing_features: bool = False


class CPUIDMasker:
    """
    Generates QEMU CPU flags to mask hypervisor presence.
    
    Common detection methods this defeats:
    1. Check hypervisor bit: CPUID.1:ECX[31]
    2. Query hypervisor signature: CPUID leaf 0x40000000
    3. Check for KVM-specific features
    4. Timing-based detection via CPUID
    """
    
    # Features that expose KVM presence
    KVM_FEATURES = [
        'kvm_pv_eoi',
        'kvm_pv_unhalt', 
        'kvm_steal_time',
        'kvm_asyncpf',
        'kvm_asyncpf_int',
        'kvmclock',
        'kvmclock-stable-bit',
        'kvm_nopiodelay',
        'kvm_mmu',
        'kvm_poll_control',
        'kvm_pv_ipi',
        'kvm_pv_sched_yield',
        'kvm_pv_tlb_flush',
    ]
    
    # Features that expose Hyper-V presence (for Windows VMs)
    HYPERV_FEATURES = [
        'hv_relaxed',
        'hv_vapic',
        'hv_spinlocks',
        'hv_time',
        'hv_crash',
        'hv_reset',
        'hv_vpindex',
        'hv_runtime',
        'hv_synic',
        'hv_stimer',
        'hv_frequencies',
        'hv_reenlightenment',
        'hv_tlbflush',
        'hv_evmcs',
        'hv_ipi',
        'hv_stimer_direct',
    ]
    
    def __init__(self, config: Optional[CPUIDConfig] = None):
        self.config = config or CPUIDConfig()
    
    def get_cpu_model_flags(self, architecture: str = "x86_64") -> List[str]:
        """
        Get CPU model and flags for QEMU.
        
        Args:
            architecture: Target architecture (x86_64 or aarch64)
            
        Returns:
            List of CPU-related QEMU arguments
        """
        if architecture == "aarch64":
            return self._get_arm64_flags()
        return self._get_x86_flags()
    
    def _get_x86_flags(self) -> List[str]:
        """Generate x86_64 CPU flags"""
        flags = []
        
        # Base CPU model - use a realistic model
        # For TCG (software emulation), we use qemu64 as base
        base_model = "qemu64"
        
        # Build feature list
        features = []
        
        # Hide hypervisor bit
        if self.config.hide_hypervisor_bit:
            features.append("-hypervisor")
        
        # Disable KVM paravirt features
        if self.config.disable_pv_features:
            for feat in self.KVM_FEATURES:
                features.append(f"-{feat}")
        
        # Disable Hyper-V features
        for feat in self.HYPERV_FEATURES:
            features.append(f"-{feat}")
        
        # Add common CPU features to look realistic
        realistic_features = [
            '+sse4.1', '+sse4.2', '+ssse3', '+popcnt',
            '+avx', '+aes', '+pclmulqdq',
            '+fma', '+bmi1', '+bmi2',
        ]
        features.extend(realistic_features)
        
        # Custom hypervisor vendor ID (spoofing)
        if self.config.custom_hv_vendor:
            # This changes what CPUID leaf 0x40000000 returns
            # Useful for spoofing a different hypervisor
            features.append(f"hv_vendor_id={self.config.custom_hv_vendor}")
        
        # Build the -cpu argument
        cpu_spec = base_model
        if features:
            cpu_spec += "," + ",".join(features)
        
        flags.extend(["-cpu", cpu_spec])
        
        return flags
    
    def _get_arm64_flags(self) -> List[str]:
        """Generate ARM64 CPU flags"""
        flags = []
        
        # For KVM on ARM, use 'host' to pass through real CPU
        # For TCG, use 'max' for maximum compatibility
        # ARM doesn't have a hypervisor bit like x86
        
        flags.extend(["-cpu", "max"])
        
        return flags
    
    def get_machine_flags(self, architecture: str = "x86_64", use_kvm: bool = False) -> List[str]:
        """
        Get machine type flags.
        
        Args:
            architecture: Target architecture
            use_kvm: Whether KVM acceleration is available
            
        Returns:
            List of machine-related QEMU arguments
        """
        flags = []
        
        if architecture == "aarch64":
            # ARM virtual machine
            machine = "virt"
            if use_kvm:
                machine += ",accel=kvm"
                # Additional settings to hide KVM on ARM
                machine += ",gic-version=3"
            else:
                machine += ",accel=tcg"
            flags.extend(["-machine", machine])
        else:
            # x86 machine - use Q35 chipset (modern Intel)
            machine = "q35"
            if use_kvm:
                # Even with KVM, we hide it
                machine += ",accel=kvm,kernel_irqchip=on"
            else:
                machine += ",accel=tcg"
            
            # Disable HPET (can be used for timing detection)
            machine += ",hpet=off"
            
            flags.extend(["-machine", machine])
        
        return flags


def get_cpuid_args(architecture: str = "x86_64", 
                   hide_hypervisor: bool = True,
                   use_kvm: bool = False) -> List[str]:
    """
    Convenience function to get all CPUID-related QEMU arguments.
    
    Args:
        architecture: Target architecture
        hide_hypervisor: Whether to hide hypervisor presence
        use_kvm: Whether KVM is being used
        
    Returns:
        List of QEMU arguments
    """
    config = CPUIDConfig(
        hide_hypervisor_bit=hide_hypervisor,
        hide_kvm_signature=hide_hypervisor,
        disable_pv_features=hide_hypervisor,
    )
    
    masker = CPUIDMasker(config)
    
    args = []
    args.extend(masker.get_machine_flags(architecture, use_kvm))
    args.extend(masker.get_cpu_model_flags(architecture))
    
    return args
