"""
SMBIOS/DMI Spoofing - Fake system management BIOS information

SMBIOS (System Management BIOS) contains hardware information that
malware often checks to detect virtual environments:
- Type 0: BIOS Information
- Type 1: System Information  
- Type 2: Baseboard Information
- Type 3: Chassis Information
- Type 4: Processor Information

This module provides realistic SMBIOS profiles from real hardware.
"""

import random
import string
import uuid
from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class SMBIOSProfile:
    """Complete SMBIOS profile for a system"""
    
    # Type 0: BIOS
    bios_vendor: str = "Dell Inc."
    bios_version: str = "A12"
    bios_date: str = "03/15/2023"
    
    # Type 1: System
    sys_manufacturer: str = "Dell Inc."
    sys_product: str = "OptiPlex 7080"
    sys_version: str = "1.0"
    sys_serial: str = ""  # Auto-generated if empty
    sys_uuid: str = ""    # Auto-generated if empty
    sys_sku: str = "Desktop"
    sys_family: str = "OptiPlex"
    
    # Type 2: Baseboard
    board_manufacturer: str = "Dell Inc."
    board_product: str = "0X8DXD"
    board_version: str = "A00"
    board_serial: str = ""  # Auto-generated if empty
    board_asset_tag: str = ""
    
    # Type 3: Chassis
    chassis_manufacturer: str = "Dell Inc."
    chassis_type: int = 3  # Desktop
    chassis_version: str = "1.0"
    chassis_serial: str = ""  # Auto-generated if empty
    chassis_asset_tag: str = ""
    
    # Type 4: Processor
    processor_manufacturer: str = "Intel(R) Corporation"
    processor_version: str = "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz"
    processor_serial: str = ""


# Realistic SMBIOS profiles from real hardware
SMBIOS_PROFILES: Dict[str, SMBIOSProfile] = {
    'dell_optiplex': SMBIOSProfile(
        bios_vendor="Dell Inc.",
        bios_version="A12",
        bios_date="03/15/2023",
        sys_manufacturer="Dell Inc.",
        sys_product="OptiPlex 7080",
        sys_version="1.0",
        sys_sku="Desktop",
        sys_family="OptiPlex",
        board_manufacturer="Dell Inc.",
        board_product="0X8DXD",
        board_version="A00",
        chassis_manufacturer="Dell Inc.",
        chassis_type=3,
        processor_manufacturer="Intel(R) Corporation",
        processor_version="Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz",
    ),
    
    'dell_latitude': SMBIOSProfile(
        bios_vendor="Dell Inc.",
        bios_version="1.15.0",
        bios_date="05/10/2023",
        sys_manufacturer="Dell Inc.",
        sys_product="Latitude 5520",
        sys_version="1.0",
        sys_sku="Laptop",
        sys_family="Latitude",
        board_manufacturer="Dell Inc.",
        board_product="0YWMR4",
        board_version="A00",
        chassis_manufacturer="Dell Inc.",
        chassis_type=10,  # Notebook
        processor_manufacturer="Intel(R) Corporation",
        processor_version="11th Gen Intel(R) Core(TM) i5-1145G7 @ 2.60GHz",
    ),
    
    'hp_prodesk': SMBIOSProfile(
        bios_vendor="HP",
        bios_version="S14 Ver. 02.09.00",
        bios_date="05/20/2023",
        sys_manufacturer="HP",
        sys_product="HP ProDesk 400 G7 Small Form Factor",
        sys_version="1.0",
        sys_sku="8QY21AV",
        sys_family="HP ProDesk",
        board_manufacturer="HP",
        board_product="8767",
        board_version="KBC Version 08.60.00",
        chassis_manufacturer="HP",
        chassis_type=3,
        processor_manufacturer="Intel(R) Corporation",
        processor_version="Intel(R) Core(TM) i5-10500 CPU @ 3.10GHz",
    ),
    
    'hp_elitebook': SMBIOSProfile(
        bios_vendor="HP",
        bios_version="T76 Ver. 01.12.00",
        bios_date="04/15/2023",
        sys_manufacturer="HP",
        sys_product="HP EliteBook 840 G8 Notebook PC",
        sys_version="1.0",
        sys_sku="3C8F3EA#ABB",
        sys_family="HP EliteBook",
        board_manufacturer="HP",
        board_product="880D",
        board_version="KBC Version 51.30.00",
        chassis_manufacturer="HP",
        chassis_type=10,
        processor_manufacturer="Intel(R) Corporation",
        processor_version="11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz",
    ),
    
    'lenovo_thinkcentre': SMBIOSProfile(
        bios_vendor="LENOVO",
        bios_version="M3CKT49A",
        bios_date="01/10/2023",
        sys_manufacturer="LENOVO",
        sys_product="ThinkCentre M920q",
        sys_version="ThinkCentre M920q",
        sys_sku="10V8S04X00",
        sys_family="ThinkCentre M920q Tiny",
        board_manufacturer="LENOVO",
        board_product="313D",
        board_version="SDK0J40697 WIN",
        chassis_manufacturer="LENOVO",
        chassis_type=35,  # Mini PC
        processor_manufacturer="Intel(R) Corporation",
        processor_version="Intel(R) Core(TM) i7-9700T CPU @ 2.00GHz",
    ),
    
    'lenovo_thinkpad': SMBIOSProfile(
        bios_vendor="LENOVO",
        bios_version="N33ET69W (1.50)",
        bios_date="06/01/2023",
        sys_manufacturer="LENOVO",
        sys_product="ThinkPad T14 Gen 2i",
        sys_version="ThinkPad T14 Gen 2i",
        sys_sku="20W0CTO1WW",
        sys_family="ThinkPad T14 Gen 2i",
        board_manufacturer="LENOVO",
        board_product="20W0CTO1WW",
        board_version="SDK0J40697 WIN",
        chassis_manufacturer="LENOVO",
        chassis_type=10,
        processor_manufacturer="Intel(R) Corporation",
        processor_version="11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz",
    ),
    
    'asus_desktop': SMBIOSProfile(
        bios_vendor="American Megatrends Inc.",
        bios_version="3801",
        bios_date="02/22/2023",
        sys_manufacturer="ASUS",
        sys_product="System Product Name",
        sys_version="System Version",
        sys_sku="SKU",
        sys_family="ASUS_MB_CNL",
        board_manufacturer="ASUSTeK COMPUTER INC.",
        board_product="ROG STRIX Z490-E GAMING",
        board_version="Rev 1.xx",
        chassis_manufacturer="Default string",
        chassis_type=3,
        processor_manufacturer="Intel(R) Corporation",
        processor_version="Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz",
    ),
}


class SMBIOSSpoofer:
    """
    Generates SMBIOS spoofing arguments for QEMU.
    
    This defeats detection methods that:
    1. Check BIOS vendor for "QEMU", "Bochs", "VirtualBox", etc.
    2. Check system manufacturer for VM indicators
    3. Check board/chassis information
    4. Look for VM-specific UUIDs
    """
    
    def __init__(self, profile: Optional[SMBIOSProfile] = None, 
                 profile_name: str = 'dell_optiplex'):
        if profile:
            self.profile = profile
        else:
            self.profile = SMBIOS_PROFILES.get(profile_name, SMBIOS_PROFILES['dell_optiplex'])
        
        self._fill_auto_values()
    
    def _fill_auto_values(self):
        """Generate random serial numbers and UUID if not set"""
        
        # System serial (format varies by manufacturer)
        if not self.profile.sys_serial:
            if 'Dell' in self.profile.sys_manufacturer:
                # Dell format: 7 alphanumeric characters
                self.profile.sys_serial = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
            elif 'HP' in self.profile.sys_manufacturer:
                # HP format: MXL + 7 alphanumeric
                self.profile.sys_serial = 'MXL' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
            elif 'LENOVO' in self.profile.sys_manufacturer:
                # Lenovo format: PF + 6 alphanumeric
                self.profile.sys_serial = 'PF' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            else:
                self.profile.sys_serial = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        
        # System UUID
        if not self.profile.sys_uuid:
            self.profile.sys_uuid = str(uuid.uuid4())
        
        # Board serial
        if not self.profile.board_serial:
            prefix = './'
            suffix = '/.'
            middle = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            self.profile.board_serial = f"{prefix}{middle}{suffix}"
        
        # Chassis serial
        if not self.profile.chassis_serial:
            self.profile.chassis_serial = self.profile.sys_serial
    
    def get_qemu_args(self) -> List[str]:
        """Generate QEMU -smbios arguments"""
        args = []
        
        # Type 0: BIOS Information
        type0 = f"type=0,vendor={self.profile.bios_vendor}"
        type0 += f",version={self.profile.bios_version}"
        type0 += f",date={self.profile.bios_date}"
        args.extend(['-smbios', type0])
        
        # Type 1: System Information
        type1 = f"type=1,manufacturer={self.profile.sys_manufacturer}"
        type1 += f",product={self.profile.sys_product}"
        type1 += f",version={self.profile.sys_version}"
        type1 += f",serial={self.profile.sys_serial}"
        type1 += f",uuid={self.profile.sys_uuid}"
        type1 += f",sku={self.profile.sys_sku}"
        type1 += f",family={self.profile.sys_family}"
        args.extend(['-smbios', type1])
        
        # Type 2: Baseboard Information
        type2 = f"type=2,manufacturer={self.profile.board_manufacturer}"
        type2 += f",product={self.profile.board_product}"
        type2 += f",version={self.profile.board_version}"
        type2 += f",serial={self.profile.board_serial}"
        args.extend(['-smbios', type2])
        
        # Type 3: Chassis Information
        type3 = f"type=3,manufacturer={self.profile.chassis_manufacturer}"
        type3 += f",type={self.profile.chassis_type}"
        type3 += f",version={self.profile.chassis_version}"
        type3 += f",serial={self.profile.chassis_serial}"
        args.extend(['-smbios', type3])
        
        # Type 4: Processor Information
        type4 = f"type=4,manufacturer={self.profile.processor_manufacturer}"
        type4 += f",version={self.profile.processor_version}"
        args.extend(['-smbios', type4])
        
        return args
    
    def get_profile_names(self) -> List[str]:
        """Get list of available profile names"""
        return list(SMBIOS_PROFILES.keys())
    
    @classmethod
    def random_profile(cls) -> 'SMBIOSSpoofer':
        """Create a spoofer with a random profile"""
        profile_name = random.choice(list(SMBIOS_PROFILES.keys()))
        return cls(profile_name=profile_name)


def get_smbios_args(profile_name: str = 'dell_optiplex') -> List[str]:
    """
    Convenience function to get SMBIOS QEMU arguments.
    
    Args:
        profile_name: Name of SMBIOS profile to use
        
    Returns:
        List of QEMU arguments
    """
    spoofer = SMBIOSSpoofer(profile_name=profile_name)
    return spoofer.get_qemu_args()
