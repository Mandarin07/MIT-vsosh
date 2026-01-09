"""
Hardware Spoofing - Fake device serial numbers, MAC addresses, etc.

Malware checks various hardware identifiers to detect virtual environments:
- Network MAC addresses (VM-specific OUIs like 52:54:00 for QEMU)
- Disk serial numbers (often default or empty in VMs)
- USB device identifiers
- PCI device IDs

This module provides realistic hardware identifiers.
"""

import random
import string
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass


# Realistic MAC address OUI prefixes (first 3 bytes)
# These are from real hardware manufacturers
MAC_OUI_PREFIXES: Dict[str, List[str]] = {
    'dell': ['D4:BE:D9', '18:03:73', '34:17:EB', 'F8:DB:88', '00:14:22'],
    'hp': ['94:57:A5', '00:21:5A', '38:63:BB', '3C:D9:2B', '00:1E:0B'],
    'lenovo': ['00:06:1B', '7C:7A:91', '6C:C2:17', '68:F7:28', '98:FA:9B'],
    'intel': ['00:1B:21', '00:1E:67', '00:15:17', '00:1C:BF', '00:13:E8'],
    'realtek': ['00:E0:4C', '52:54:00', '00:0A:CD', '4C:ED:FB', '00:40:F4'],
    'broadcom': ['00:10:18', '00:1A:2B', '00:24:D6', '60:33:4B', '44:94:FC'],
    'samsung': ['00:12:47', '00:21:4C', '84:25:DB', 'F0:1F:AF', '94:35:0A'],
    'asus': ['00:1D:60', '00:15:F2', '2C:4D:54', '40:16:7E', 'E0:3F:49'],
}

# Disk serial number prefixes for different manufacturers
DISK_SERIAL_PREFIXES: Dict[str, str] = {
    'western_digital': 'WD-WCAV',
    'seagate': 'ST',
    'samsung': 'S',
    'crucial': 'CT',
    'sandisk': 'SD',
    'kingston': 'K',
    'intel': 'CVFT',
    'toshiba': 'Y',
}


@dataclass
class HardwareConfig:
    """Hardware spoofing configuration"""
    
    # Network
    mac_vendor: str = 'dell'
    custom_mac: Optional[str] = None
    
    # Storage
    disk_vendor: str = 'western_digital'
    custom_disk_serial: Optional[str] = None
    
    # USB
    usb_vendor_id: int = 0x046d  # Logitech
    usb_product_id: int = 0xc52b  # Unifying Receiver
    
    # Generate unique identifiers
    randomize: bool = True


class HardwareSpoofer:
    """
    Generates realistic hardware identifiers for QEMU.
    
    This defeats detection methods that:
    1. Check MAC address OUI for VM vendors
    2. Look for empty or default disk serials
    3. Check for VM-specific PCI/USB devices
    """
    
    def __init__(self, config: Optional[HardwareConfig] = None):
        self.config = config or HardwareConfig()
    
    def generate_mac_address(self) -> str:
        """Generate a realistic MAC address"""
        if self.config.custom_mac:
            return self.config.custom_mac
        
        # Get OUI prefix from vendor
        oui_list = MAC_OUI_PREFIXES.get(self.config.mac_vendor, MAC_OUI_PREFIXES['intel'])
        oui = random.choice(oui_list)
        
        # Generate random device portion (last 3 bytes)
        device_bytes = [random.randint(0, 255) for _ in range(3)]
        device_part = ':'.join(f'{b:02X}' for b in device_bytes)
        
        return f"{oui}:{device_part}"
    
    def generate_disk_serial(self) -> str:
        """Generate a realistic disk serial number"""
        if self.config.custom_disk_serial:
            return self.config.custom_disk_serial
        
        prefix = DISK_SERIAL_PREFIXES.get(self.config.disk_vendor, 'WD-WCAV')
        
        # Different formats for different vendors
        if self.config.disk_vendor == 'western_digital':
            # WD format: WD-WCAV + 8 alphanumeric
            suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        elif self.config.disk_vendor == 'seagate':
            # Seagate format: ST + 8 digits + 3 letters
            suffix = ''.join(random.choices(string.digits, k=8))
            suffix += ''.join(random.choices(string.ascii_uppercase, k=3))
        elif self.config.disk_vendor == 'samsung':
            # Samsung format: S + model + serial
            suffix = ''.join(random.choices(string.digits, k=3))
            suffix += 'NX' + ''.join(random.choices(string.digits, k=7))
        else:
            suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
        
        return f"{prefix}{suffix}"
    
    def get_network_args(self, network_enabled: bool = False) -> List[str]:
        """Generate network device arguments"""
        args = []
        
        mac = self.generate_mac_address()
        
        if network_enabled:
            # User-mode networking with realistic MAC
            args.extend([
                '-netdev', 'user,id=net0',
                '-device', f'virtio-net-pci,netdev=net0,mac={mac}'
            ])
        else:
            # No network, but still define NIC with realistic MAC
            # This is useful if we later enable networking
            args.extend(['-nic', 'none'])
        
        return args
    
    def get_storage_args(self, image_path: str, drive_id: str = 'disk0') -> List[str]:
        """Generate storage device arguments"""
        args = []
        
        serial = self.generate_disk_serial()
        
        # Use IDE for more realistic appearance (SATA/AHCI)
        # virtio is faster but more detectable
        args.extend([
            '-drive', f'file={image_path},if=none,id={drive_id},format=qcow2,serial={serial}',
            '-device', f'ide-hd,drive={drive_id},bus=ide.0'
        ])
        
        return args
    
    def get_usb_args(self) -> List[str]:
        """Generate USB device arguments"""
        args = []
        
        # USB controller
        args.extend(['-device', 'qemu-xhci,id=xhci'])
        
        # Keyboard (looks like real USB keyboard)
        args.extend(['-device', 'usb-kbd,id=kbd0'])
        
        # Mouse
        args.extend(['-device', 'usb-mouse,id=mouse0'])
        
        # Tablet (for better mouse tracking)
        args.extend(['-device', 'usb-tablet,id=tablet0'])
        
        return args
    
    def get_audio_args(self) -> List[str]:
        """Generate audio device arguments"""
        args = []
        
        # Intel HDA (High Definition Audio) - common in real PCs
        args.extend([
            '-device', 'intel-hda',
            '-device', 'hda-duplex'
        ])
        
        return args
    
    def get_display_args(self, display_type: str = 'none') -> List[str]:
        """Generate display arguments"""
        args = []
        
        if display_type == 'none':
            args.extend(['-display', 'none', '-nographic'])
        elif display_type == 'vnc':
            args.extend(['-vnc', ':0'])
        elif display_type == 'gtk':
            args.extend(['-display', 'gtk'])
        elif display_type == 'spice':
            args.extend([
                '-spice', 'port=5930,disable-ticketing=on',
                '-device', 'qxl-vga'
            ])
        
        return args
    
    def get_all_args(self, image_path: str, network_enabled: bool = False,
                     display_type: str = 'none') -> List[str]:
        """Get all hardware spoofing arguments"""
        args = []
        
        args.extend(self.get_storage_args(image_path))
        args.extend(self.get_network_args(network_enabled))
        args.extend(self.get_usb_args())
        args.extend(self.get_audio_args())
        args.extend(self.get_display_args(display_type))
        
        # Random number generator (looks like real hardware)
        args.extend(['-device', 'virtio-rng-pci'])
        
        return args


def get_hardware_args(image_path: str, 
                     mac_vendor: str = 'dell',
                     disk_vendor: str = 'western_digital',
                     network_enabled: bool = False) -> List[str]:
    """
    Convenience function to get hardware spoofing arguments.
    
    Args:
        image_path: Path to disk image
        mac_vendor: MAC address vendor
        disk_vendor: Disk serial vendor
        network_enabled: Whether to enable networking
        
    Returns:
        List of QEMU arguments
    """
    config = HardwareConfig(
        mac_vendor=mac_vendor,
        disk_vendor=disk_vendor,
    )
    
    spoofer = HardwareSpoofer(config)
    return spoofer.get_all_args(image_path, network_enabled)
