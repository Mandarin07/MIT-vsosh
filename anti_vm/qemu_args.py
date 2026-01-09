"""
QEMU Arguments Builder - Combines all anti-VM techniques

This module provides a unified interface to build QEMU command-line
arguments with all anti-VM detection countermeasures applied.
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass

from .cpuid_mask import CPUIDMasker, CPUIDConfig
from .smbios_spoof import SMBIOSSpoofer, SMBIOS_PROFILES
from .hardware_spoof import HardwareSpoofer, HardwareConfig
from .timing_fix import TimingFixer, TimingConfig, get_timing_cpu_flags


@dataclass
class AntiVMQEMUConfig:
    """Configuration for anti-VM QEMU setup"""
    
    # Architecture
    architecture: str = "x86_64"  # x86_64 or aarch64
    use_kvm: bool = False
    
    # Resources
    ram_mb: int = 4096
    cpus: int = 4
    
    # Storage
    disk_image: str = ""
    
    # SMBIOS profile
    smbios_profile: str = "dell_optiplex"
    
    # Hardware
    mac_vendor: str = "dell"
    disk_vendor: str = "western_digital"
    
    # Network
    network_enabled: bool = False
    
    # Display
    display: str = "none"  # none, vnc, gtk, spice
    vnc_display: int = 0
    
    # Timing
    stabilize_timing: bool = True
    tsc_frequency: int = 3600000000
    
    # CPUID
    hide_hypervisor: bool = True
    hide_kvm_features: bool = True
    
    # Communication sockets
    monitor_socket: Optional[str] = None
    serial_socket: Optional[str] = None
    agent_socket: Optional[str] = None


class QEMUArgsBuilder:
    """
    Builds QEMU command-line arguments with anti-VM measures.
    
    This class combines all the anti-VM techniques into a single
    coherent QEMU configuration.
    """
    
    def __init__(self, config: AntiVMQEMUConfig):
        self.config = config
        
        # Initialize components
        self.cpuid_config = CPUIDConfig(
            hide_hypervisor_bit=config.hide_hypervisor,
            hide_kvm_signature=config.hide_kvm_features,
            disable_pv_features=config.hide_kvm_features,
        )
        self.cpuid_masker = CPUIDMasker(self.cpuid_config)
        
        self.smbios_spoofer = SMBIOSSpoofer(profile_name=config.smbios_profile)
        
        self.hardware_config = HardwareConfig(
            mac_vendor=config.mac_vendor,
            disk_vendor=config.disk_vendor,
        )
        self.hardware_spoofer = HardwareSpoofer(self.hardware_config)
        
        self.timing_config = TimingConfig(
            enable_invtsc=config.stabilize_timing,
            tsc_frequency=config.tsc_frequency,
            disable_hpet=True,
        )
        self.timing_fixer = TimingFixer(self.timing_config)
    
    def build_args(self) -> List[str]:
        """Build complete QEMU command arguments"""
        args = []
        
        # QEMU binary
        if self.config.architecture == "aarch64":
            args.append("qemu-system-aarch64")
        else:
            args.append("qemu-system-x86_64")
        
        # Machine and CPU
        args.extend(self._build_machine_args())
        args.extend(self._build_cpu_args())
        
        # Memory
        args.extend(["-m", str(self.config.ram_mb)])
        
        # SMP
        args.extend(["-smp", str(self.config.cpus)])
        
        # SMBIOS
        if self.config.architecture == "x86_64":
            args.extend(self.smbios_spoofer.get_qemu_args())
        
        # Storage
        if self.config.disk_image:
            args.extend(self._build_storage_args())
        
        # Network
        args.extend(self._build_network_args())
        
        # Display
        args.extend(self._build_display_args())
        
        # USB and audio
        args.extend(self._build_device_args())
        
        # Timing
        args.extend(self.timing_fixer.get_all_timing_args())
        
        # Communication sockets
        args.extend(self._build_socket_args())
        
        return args
    
    def _build_machine_args(self) -> List[str]:
        """Build machine type arguments"""
        args = []
        
        if self.config.architecture == "aarch64":
            machine = "virt"
            if self.config.use_kvm:
                machine += ",accel=kvm,gic-version=3"
            else:
                machine += ",accel=tcg"
            args.extend(["-machine", machine])
        else:
            machine = "q35"
            if self.config.use_kvm:
                machine += ",accel=kvm"
            else:
                machine += ",accel=tcg"
            
            # Disable HPET for timing reasons
            machine += ",hpet=off"
            
            args.extend(["-machine", machine])
        
        return args
    
    def _build_cpu_args(self) -> List[str]:
        """Build CPU arguments with anti-detection"""
        args = []
        
        if self.config.architecture == "aarch64":
            if self.config.use_kvm:
                args.extend(["-cpu", "host"])
            else:
                args.extend(["-cpu", "max"])
        else:
            # x86_64
            cpu_flags = ["qemu64"]
            
            # Hide hypervisor
            if self.config.hide_hypervisor:
                cpu_flags.append("-hypervisor")
            
            # Hide KVM features
            if self.config.hide_kvm_features:
                kvm_features = [
                    "kvm_pv_eoi", "kvm_pv_unhalt", "kvm_steal_time",
                    "kvmclock", "kvmclock-stable-bit"
                ]
                for feat in kvm_features:
                    cpu_flags.append(f"-{feat}")
            
            # Timing features
            if self.config.stabilize_timing:
                cpu_flags.extend(get_timing_cpu_flags(
                    stabilize=True,
                    tsc_frequency=self.config.tsc_frequency
                ))
            
            # Realistic CPU features
            realistic_features = [
                "+sse4.1", "+sse4.2", "+ssse3", "+popcnt",
                "+avx", "+aes", "+pclmulqdq"
            ]
            cpu_flags.extend(realistic_features)
            
            args.extend(["-cpu", ",".join(cpu_flags)])
        
        return args
    
    def _build_storage_args(self) -> List[str]:
        """Build storage arguments"""
        args = []
        
        serial = self.hardware_spoofer.generate_disk_serial()
        
        args.extend([
            "-drive", f"file={self.config.disk_image},if=none,id=disk0,format=qcow2,serial={serial}",
        ])
        
        if self.config.architecture == "aarch64":
            args.extend(["-device", "virtio-blk-pci,drive=disk0"])
        else:
            # Use IDE for more realistic appearance
            args.extend(["-device", "ide-hd,drive=disk0,bus=ide.0"])
        
        return args
    
    def _build_network_args(self) -> List[str]:
        """Build network arguments"""
        args = []
        
        mac = self.hardware_spoofer.generate_mac_address()
        
        if self.config.network_enabled:
            args.extend([
                "-netdev", "user,id=net0",
                "-device", f"virtio-net-pci,netdev=net0,mac={mac}"
            ])
        else:
            args.extend(["-nic", "none"])
        
        return args
    
    def _build_display_args(self) -> List[str]:
        """Build display arguments"""
        args = []
        
        if self.config.display == "none":
            args.extend(["-display", "none", "-nographic"])
        elif self.config.display == "vnc":
            args.extend(["-vnc", f":{self.config.vnc_display}"])
        elif self.config.display == "gtk":
            args.extend(["-display", "gtk"])
        elif self.config.display == "spice":
            port = 5930 + self.config.vnc_display
            args.extend([
                "-spice", f"port={port},disable-ticketing=on",
                "-device", "qxl-vga"
            ])
        
        return args
    
    def _build_device_args(self) -> List[str]:
        """Build device emulation arguments"""
        args = []
        
        # USB controller and devices
        args.extend(["-device", "qemu-xhci,id=xhci"])
        args.extend(["-device", "usb-kbd,id=kbd0"])
        args.extend(["-device", "usb-mouse,id=mouse0"])
        args.extend(["-device", "usb-tablet,id=tablet0"])
        
        # Audio
        args.extend(["-device", "intel-hda"])
        args.extend(["-device", "hda-duplex"])
        
        # RNG
        args.extend(["-device", "virtio-rng-pci"])
        
        return args
    
    def _build_socket_args(self) -> List[str]:
        """Build communication socket arguments"""
        args = []
        
        # QMP monitor
        if self.config.monitor_socket:
            args.extend(["-qmp", f"unix:{self.config.monitor_socket},server,nowait"])
        
        # Serial console
        if self.config.serial_socket:
            args.extend([
                "-chardev", f"socket,id=serial0,path={self.config.serial_socket},server=on,wait=off",
                "-serial", "chardev:serial0"
            ])
        
        # Guest agent (virtio-serial)
        if self.config.agent_socket:
            args.extend([
                "-device", "virtio-serial-pci",
                "-chardev", f"socket,id=agent0,path={self.config.agent_socket},server=on,wait=off",
                "-device", "virtserialport,chardev=agent0,name=org.sandbox.agent"
            ])
        
        return args
    
    def get_command_string(self) -> str:
        """Get the complete command as a string"""
        return ' '.join(self.build_args())


def build_anti_vm_args(
    architecture: str = "x86_64",
    disk_image: str = "",
    ram_mb: int = 4096,
    cpus: int = 4,
    smbios_profile: str = "dell_optiplex",
    hide_hypervisor: bool = True,
    network_enabled: bool = False,
    monitor_socket: Optional[str] = None,
    serial_socket: Optional[str] = None,
    agent_socket: Optional[str] = None,
) -> List[str]:
    """
    Convenience function to build anti-VM QEMU arguments.
    
    Args:
        architecture: Target architecture (x86_64 or aarch64)
        disk_image: Path to disk image
        ram_mb: RAM in megabytes
        cpus: Number of CPUs
        smbios_profile: SMBIOS profile name
        hide_hypervisor: Whether to hide hypervisor presence
        network_enabled: Whether to enable networking
        monitor_socket: Path for QMP monitor socket
        serial_socket: Path for serial console socket
        agent_socket: Path for guest agent socket
        
    Returns:
        List of QEMU arguments
    """
    config = AntiVMQEMUConfig(
        architecture=architecture,
        disk_image=disk_image,
        ram_mb=ram_mb,
        cpus=cpus,
        smbios_profile=smbios_profile,
        hide_hypervisor=hide_hypervisor,
        hide_kvm_features=hide_hypervisor,
        network_enabled=network_enabled,
        monitor_socket=monitor_socket,
        serial_socket=serial_socket,
        agent_socket=agent_socket,
    )
    
    builder = QEMUArgsBuilder(config)
    return builder.build_args()
