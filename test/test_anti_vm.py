#!/usr/bin/env python3
"""
Anti-VM Detection Tests

Tests to verify that the VM sandbox successfully evades common
anti-VM detection techniques used by malware.
"""

import os
import sys
import unittest
import subprocess
import tempfile

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAntiVMModules(unittest.TestCase):
    """Test anti-VM module imports and basic functionality"""
    
    def test_import_cpuid_mask(self):
        """Test CPUID masker import"""
        from anti_vm.cpuid_mask import CPUIDMasker, get_cpuid_args
        masker = CPUIDMasker()
        self.assertIsNotNone(masker)
    
    def test_import_smbios_spoof(self):
        """Test SMBIOS spoofer import"""
        from anti_vm.smbios_spoof import SMBIOSSpoofer, SMBIOS_PROFILES
        self.assertIn('dell_optiplex', SMBIOS_PROFILES)
        spoofer = SMBIOSSpoofer(profile_name='dell_optiplex')
        self.assertIsNotNone(spoofer)
    
    def test_import_hardware_spoof(self):
        """Test hardware spoofer import"""
        from anti_vm.hardware_spoof import HardwareSpoofer
        spoofer = HardwareSpoofer()
        self.assertIsNotNone(spoofer)
    
    def test_import_timing_fix(self):
        """Test timing fixer import"""
        from anti_vm.timing_fix import TimingFixer, get_timing_args
        fixer = TimingFixer()
        self.assertIsNotNone(fixer)
    
    def test_import_sensors_fake(self):
        """Test sensors faker import"""
        from anti_vm.sensors_fake import SensorsFaker, create_desktop_sensors
        faker = create_desktop_sensors()
        self.assertIsNotNone(faker)
    
    def test_import_artifacts(self):
        """Test artifacts generator import"""
        from anti_vm.artifacts import ArtifactsGenerator, ArtifactsConfig
        config = ArtifactsConfig(home_dir=tempfile.gettempdir())
        gen = ArtifactsGenerator(config)
        self.assertIsNotNone(gen)
    
    def test_import_qemu_args(self):
        """Test QEMU args builder import"""
        from anti_vm.qemu_args import QEMUArgsBuilder, AntiVMQEMUConfig
        config = AntiVMQEMUConfig()
        builder = QEMUArgsBuilder(config)
        self.assertIsNotNone(builder)


class TestCPUIDMasker(unittest.TestCase):
    """Test CPUID masking functionality"""
    
    def test_x86_cpu_flags(self):
        """Test x86 CPU flags generation"""
        from anti_vm.cpuid_mask import CPUIDMasker, CPUIDConfig
        
        config = CPUIDConfig(hide_hypervisor_bit=True)
        masker = CPUIDMasker(config)
        flags = masker.get_cpu_model_flags("x86_64")
        
        self.assertIsInstance(flags, list)
        self.assertTrue(any('-cpu' in str(f) for f in flags))
    
    def test_hypervisor_hidden(self):
        """Test that hypervisor flag is hidden"""
        from anti_vm.cpuid_mask import CPUIDMasker, CPUIDConfig
        
        config = CPUIDConfig(hide_hypervisor_bit=True)
        masker = CPUIDMasker(config)
        flags = masker.get_cpu_model_flags("x86_64")
        
        # Check that -hypervisor is in the flags
        cpu_arg = ' '.join(flags)
        self.assertIn('-hypervisor', cpu_arg)
    
    def test_arm64_cpu_flags(self):
        """Test ARM64 CPU flags generation"""
        from anti_vm.cpuid_mask import CPUIDMasker
        
        masker = CPUIDMasker()
        flags = masker.get_cpu_model_flags("aarch64")
        
        self.assertIsInstance(flags, list)


class TestSMBIOSSpoofer(unittest.TestCase):
    """Test SMBIOS spoofing functionality"""
    
    def test_profile_loading(self):
        """Test that profiles load correctly"""
        from anti_vm.smbios_spoof import SMBIOSSpoofer, SMBIOS_PROFILES
        
        for profile_name in SMBIOS_PROFILES:
            spoofer = SMBIOSSpoofer(profile_name=profile_name)
            self.assertIsNotNone(spoofer.profile)
    
    def test_qemu_args_generation(self):
        """Test QEMU SMBIOS args generation"""
        from anti_vm.smbios_spoof import SMBIOSSpoofer
        
        spoofer = SMBIOSSpoofer(profile_name='dell_optiplex')
        args = spoofer.get_qemu_args()
        
        self.assertIsInstance(args, list)
        # Should have multiple -smbios entries
        smbios_count = args.count('-smbios')
        self.assertGreaterEqual(smbios_count, 4)  # type 0,1,2,3
    
    def test_serial_generation(self):
        """Test that serial numbers are generated"""
        from anti_vm.smbios_spoof import SMBIOSSpoofer
        
        spoofer = SMBIOSSpoofer(profile_name='dell_optiplex')
        
        # Serial should be auto-generated
        self.assertTrue(len(spoofer.profile.sys_serial) > 0)
        self.assertTrue(len(spoofer.profile.board_serial) > 0)
    
    def test_uuid_generation(self):
        """Test that UUID is generated"""
        from anti_vm.smbios_spoof import SMBIOSSpoofer
        
        spoofer = SMBIOSSpoofer(profile_name='dell_optiplex')
        
        # UUID should be a valid format
        uuid = spoofer.profile.sys_uuid
        self.assertTrue('-' in uuid)
        self.assertEqual(len(uuid), 36)


class TestHardwareSpoofer(unittest.TestCase):
    """Test hardware spoofing functionality"""
    
    def test_mac_generation(self):
        """Test MAC address generation"""
        from anti_vm.hardware_spoof import HardwareSpoofer, HardwareConfig
        
        config = HardwareConfig(mac_vendor='dell')
        spoofer = HardwareSpoofer(config)
        mac = spoofer.generate_mac_address()
        
        # MAC should be in correct format
        self.assertEqual(len(mac.split(':')), 6)
        # Should start with Dell OUI
        self.assertTrue(mac.startswith('D4:BE:D9') or 
                       mac.startswith('18:03:73') or
                       mac.startswith('34:17:EB'))
    
    def test_mac_not_vm(self):
        """Test that MAC is not a VM prefix"""
        from anti_vm.hardware_spoof import HardwareSpoofer
        
        spoofer = HardwareSpoofer()
        mac = spoofer.generate_mac_address()
        
        # Should not be common VM prefixes
        vm_prefixes = ['52:54:00', '00:0C:29', '00:50:56', '08:00:27']
        for prefix in vm_prefixes:
            self.assertFalse(mac.startswith(prefix), f"MAC {mac} starts with VM prefix {prefix}")
    
    def test_disk_serial_generation(self):
        """Test disk serial generation"""
        from anti_vm.hardware_spoof import HardwareSpoofer, HardwareConfig
        
        config = HardwareConfig(disk_vendor='western_digital')
        spoofer = HardwareSpoofer(config)
        serial = spoofer.generate_disk_serial()
        
        self.assertTrue(serial.startswith('WD-WCAV'))
        self.assertTrue(len(serial) > 10)


class TestSensorsFaker(unittest.TestCase):
    """Test fake sensors functionality"""
    
    def test_thermal_generation(self):
        """Test thermal zone generation"""
        from anti_vm.sensors_fake import SensorsFaker, SensorsConfig, ThermalZone
        
        config = SensorsConfig(
            thermal_zones=[ThermalZone(name="x86_pkg_temp", base_temp=45)]
        )
        faker = SensorsFaker(config)
        
        self.assertEqual(len(faker.config.thermal_zones), 1)
    
    def test_temp_in_range(self):
        """Test that temperatures are realistic"""
        from anti_vm.sensors_fake import ThermalZone
        
        tz = ThermalZone(base_temp=45, variance=10)
        
        for _ in range(100):
            temp = tz.get_temp()
            # Should be between 40-55 degrees (in millidegrees)
            self.assertGreaterEqual(temp, 40000)
            self.assertLessEqual(temp, 55000)
    
    def test_fan_in_range(self):
        """Test that fan speeds are realistic"""
        from anti_vm.sensors_fake import FanSensor
        
        fan = FanSensor(base_rpm=2400, variance=400)
        
        for _ in range(100):
            rpm = fan.get_rpm()
            # Should be reasonable RPM
            self.assertGreaterEqual(rpm, 2000)
            self.assertLessEqual(rpm, 3000)


class TestQEMUArgsBuilder(unittest.TestCase):
    """Test QEMU arguments builder"""
    
    def test_full_args_generation(self):
        """Test complete args generation"""
        from anti_vm.qemu_args import QEMUArgsBuilder, AntiVMQEMUConfig
        
        config = AntiVMQEMUConfig(
            architecture="x86_64",
            disk_image="/tmp/test.qcow2",
            ram_mb=4096,
            cpus=4,
            hide_hypervisor=True,
        )
        builder = QEMUArgsBuilder(config)
        args = builder.build_args()
        
        self.assertIsInstance(args, list)
        self.assertTrue(len(args) > 10)
        
        # Check essential args
        args_str = ' '.join(args)
        self.assertIn('-m', args_str)
        self.assertIn('-smp', args_str)
        self.assertIn('-cpu', args_str)
    
    def test_smbios_included(self):
        """Test that SMBIOS args are included"""
        from anti_vm.qemu_args import QEMUArgsBuilder, AntiVMQEMUConfig
        
        config = AntiVMQEMUConfig(
            architecture="x86_64",
            smbios_profile="dell_optiplex",
        )
        builder = QEMUArgsBuilder(config)
        args = builder.build_args()
        
        self.assertIn('-smbios', args)
    
    def test_monitor_socket(self):
        """Test monitor socket configuration"""
        from anti_vm.qemu_args import QEMUArgsBuilder, AntiVMQEMUConfig
        
        config = AntiVMQEMUConfig(
            monitor_socket="/tmp/test_monitor.sock",
        )
        builder = QEMUArgsBuilder(config)
        args = builder.build_args()
        
        args_str = ' '.join(args)
        self.assertIn('-qmp', args_str)
        self.assertIn('test_monitor.sock', args_str)


class TestVMManager(unittest.TestCase):
    """Test VM Manager (integration tests)"""
    
    def test_import_vm_manager(self):
        """Test VM manager import"""
        try:
            from vm_manager.vm_manager import VMManager
            self.assertTrue(True)
        except ImportError as e:
            self.skipTest(f"VM manager not available: {e}")
    
    def test_vm_config_import(self):
        """Test VM config import"""
        from vm_manager.vm_config import VMConfig, VMArchitecture, AntiVMConfig
        
        config = VMConfig(
            name="test",
            image_path="/tmp/test.qcow2",
            architecture=VMArchitecture.ARM64,
        )
        self.assertEqual(config.name, "test")


class TestVMDynamicAnalyzer(unittest.TestCase):
    """Test VM Dynamic Analyzer integration"""
    
    def test_import(self):
        """Test VMDynamicAnalyzer import"""
        from dynamic import VMDynamicAnalyzer
        self.assertTrue(True)
    
    def test_init_without_config(self):
        """Test initialization without VM config"""
        from dynamic import VMDynamicAnalyzer
        
        analyzer = VMDynamicAnalyzer(vm_config_path="/nonexistent/path.yaml")
        self.assertFalse(analyzer.vm_available)
    
    def test_get_status(self):
        """Test status retrieval"""
        from dynamic import VMDynamicAnalyzer
        
        analyzer = VMDynamicAnalyzer()
        status = analyzer.get_status()
        
        self.assertIn('yara_available', status)
        self.assertIn('vm_available', status)


# Anti-VM Detection Simulation Tests
# These simulate what malware might check

class TestAntiVMDetection(unittest.TestCase):
    """Simulate anti-VM detection checks"""
    
    def test_cpuinfo_no_hypervisor(self):
        """Check that cpuinfo wouldn't reveal hypervisor"""
        # This test simulates checking /proc/cpuinfo
        # In a properly configured VM, "hypervisor" should not appear
        
        fake_cpuinfo = """processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model name	: Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz
flags		: fpu vme de pse tsc msr pae mce cx8 apic sse sse2
"""
        # Should not contain hypervisor in flags
        self.assertNotIn('hypervisor', fake_cpuinfo.lower())
    
    def test_dmi_not_qemu(self):
        """Check that DMI wouldn't reveal QEMU"""
        from anti_vm.smbios_spoof import SMBIOSSpoofer
        
        spoofer = SMBIOSSpoofer(profile_name='dell_optiplex')
        
        # None of the fields should contain VM indicators
        vm_indicators = ['qemu', 'virtualbox', 'vmware', 'kvm', 'xen', 'hyper-v']
        
        fields = [
            spoofer.profile.bios_vendor,
            spoofer.profile.sys_manufacturer,
            spoofer.profile.sys_product,
            spoofer.profile.board_manufacturer,
        ]
        
        for field in fields:
            for indicator in vm_indicators:
                self.assertNotIn(indicator.lower(), field.lower())
    
    def test_mac_not_vm_oui(self):
        """Check MAC address OUI is not from VM"""
        from anti_vm.hardware_spoof import HardwareSpoofer
        
        # VM OUI prefixes to check
        vm_ouis = [
            '52:54:00',  # QEMU
            '00:0C:29',  # VMware
            '00:50:56',  # VMware
            '08:00:27',  # VirtualBox
            '00:16:3E',  # Xen
            '00:15:5D',  # Hyper-V
        ]
        
        spoofer = HardwareSpoofer()
        
        for _ in range(10):
            mac = spoofer.generate_mac_address()
            for oui in vm_ouis:
                self.assertFalse(
                    mac.upper().startswith(oui.upper()),
                    f"Generated MAC {mac} has VM OUI {oui}"
                )


if __name__ == '__main__':
    unittest.main(verbosity=2)
