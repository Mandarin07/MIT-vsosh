"""
QEMU Launcher - Handles QEMU process management and command generation
"""

import os
import subprocess
import time
import signal
import socket
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

from .vm_config import VMConfig, VMArchitecture, AntiVMConfig

logger = logging.getLogger(__name__)


@dataclass
class QEMUProcess:
    """Represents a running QEMU process"""
    process: subprocess.Popen
    config: VMConfig
    monitor_socket: str
    serial_socket: str
    pid: int
    
    def is_running(self) -> bool:
        return self.process.poll() is None
    
    def terminate(self, timeout: int = 5):
        """Gracefully terminate QEMU"""
        if self.is_running():
            self.process.terminate()
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


class QEMULauncher:
    """
    Launches and manages QEMU virtual machines with anti-VM configurations
    """
    
    def __init__(self, sockets_dir: str = "/tmp/vm_sandbox"):
        self.sockets_dir = sockets_dir
        self._processes: Dict[str, QEMUProcess] = {}
        os.makedirs(sockets_dir, exist_ok=True)
    
    def _check_qemu_available(self, binary: str) -> bool:
        """Check if QEMU binary is available"""
        try:
            result = subprocess.run(['which', binary], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_kvm_available(self) -> bool:
        """Check if KVM acceleration is available"""
        return os.path.exists('/dev/kvm') and os.access('/dev/kvm', os.R_OK | os.W_OK)
    
    def _generate_base_args(self, config: VMConfig) -> List[str]:
        """Generate base QEMU arguments"""
        args = [config.qemu_binary]
        
        # Machine type
        if config.architecture == VMArchitecture.ARM64:
            args.extend(['-machine', 'virt,gic-version=3'])
            args.extend(['-cpu', 'max'])
        else:
            args.extend(['-machine', 'q35,accel=tcg'])
            args.extend(['-cpu', 'qemu64'])
        
        # Memory and CPUs
        args.extend(['-m', str(config.ram_mb)])
        args.extend(['-smp', str(config.cpus)])
        
        # KVM acceleration (only for ARM64 on ARM host)
        if config.enable_kvm and self._check_kvm_available():
            if config.architecture == VMArchitecture.ARM64:
                args[args.index('virt,gic-version=3')] = 'virt,gic-version=3,accel=kvm'
                args[args.index('max')] = 'host'
        
        return args
    
    def _generate_storage_args(self, config: VMConfig, anti_vm: AntiVMConfig) -> List[str]:
        """Generate storage-related arguments"""
        args = []
        
        # Generate realistic disk serial
        import random
        serial = f"{anti_vm.disk_serial_prefix}{random.randint(10000000, 99999999)}"
        
        # Main disk
        args.extend([
            '-drive', f'file={config.image_path},if=none,id=disk0,format=qcow2,serial={serial}',
        ])
        
        if config.architecture == VMArchitecture.ARM64:
            args.extend(['-device', 'virtio-blk-pci,drive=disk0'])
        else:
            args.extend(['-device', 'ide-hd,drive=disk0,bus=ide.0'])
        
        return args
    
    def _generate_network_args(self, config: VMConfig, anti_vm: AntiVMConfig) -> List[str]:
        """Generate network arguments with realistic MAC"""
        args = []
        
        # Generate realistic MAC address
        import random
        mac_suffix = ':'.join([f'{random.randint(0, 255):02x}' for _ in range(3)])
        mac_address = f"{anti_vm.mac_prefix}:{mac_suffix}"
        
        if config.network_enabled:
            args.extend([
                '-netdev', 'user,id=net0',
                '-device', f'virtio-net-pci,netdev=net0,mac={mac_address}'
            ])
        else:
            # No network for sandbox isolation
            args.extend(['-nic', 'none'])
        
        return args
    
    def _generate_smbios_args(self, anti_vm: AntiVMConfig) -> List[str]:
        """Generate SMBIOS/DMI spoofing arguments"""
        args = []
        
        # SMBIOS profiles with realistic data
        profiles = {
            'dell_optiplex': {
                'type0': 'vendor=Dell Inc.,version=A12,date=03/15/2023',
                'type1': 'manufacturer=Dell Inc.,product=OptiPlex 7080,version=1.0,serial=ABC1234567,uuid=550e8400-e29b-41d4-a716-446655440000',
                'type2': 'manufacturer=Dell Inc.,product=0X8DXD,version=A00,serial=.XYZ9876543.',
                'type3': 'manufacturer=Dell Inc.,type=3,serial=GHI789012',
                'type4': 'manufacturer=Intel(R) Corporation,version=Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz',
            },
            'hp_prodesk': {
                'type0': 'vendor=HP,version=S14 Ver. 02.09.00,date=05/20/2023',
                'type1': 'manufacturer=HP,product=HP ProDesk 400 G7,version=1.0,serial=MXL1234ABC',
                'type2': 'manufacturer=HP,product=8767,version=KBC Version 08.60.00,serial=PWXYZ12345',
                'type3': 'manufacturer=HP,type=3,serial=MXL1234ABC',
                'type4': 'manufacturer=Intel(R) Corporation,version=Intel(R) Core(TM) i5-10500 CPU @ 3.10GHz',
            },
            'lenovo_thinkcentre': {
                'type0': 'vendor=LENOVO,version=M3CKT49A,date=01/10/2023',
                'type1': 'manufacturer=LENOVO,product=ThinkCentre M920q,version=ThinkCentre M920q,serial=PF2XXXXX',
                'type2': 'manufacturer=LENOVO,product=313D,version=SDK0J40697 WIN,serial=L1HFXXX01XX',
                'type3': 'manufacturer=LENOVO,type=3,serial=PF2XXXXX',
                'type4': 'manufacturer=Intel(R) Corporation,version=Intel(R) Core(TM) i7-9700T CPU @ 2.00GHz',
            },
        }
        
        profile = profiles.get(anti_vm.smbios_profile, profiles['dell_optiplex'])
        
        # Apply custom SMBIOS overrides if provided
        if anti_vm.custom_smbios:
            profile.update(anti_vm.custom_smbios)
        
        for smbios_type, data in profile.items():
            type_num = smbios_type.replace('type', '')
            args.extend(['-smbios', f'type={type_num},{data}'])
        
        return args
    
    def _generate_cpu_args(self, config: VMConfig, anti_vm: AntiVMConfig) -> List[str]:
        """Generate CPU arguments with anti-VM settings"""
        args = []
        
        if config.architecture == VMArchitecture.X64:
            # For x64 emulation, use TCG with anti-detection
            cpu_flags = ['qemu64']
            
            if anti_vm.hide_hypervisor:
                cpu_flags.append('-hypervisor')
            
            if anti_vm.stabilize_tsc:
                cpu_flags.append('+invtsc')
            
            # Hide KVM-specific features
            if anti_vm.hide_kvm_signature:
                cpu_flags.extend(['-kvm_pv_eoi', '-kvm_pv_unhalt', '-kvm_steal_time'])
            
            args.extend(['-cpu', ','.join(cpu_flags)])
        
        return args
    
    def _generate_display_args(self, config: VMConfig) -> List[str]:
        """Generate display arguments"""
        args = []
        
        if config.display == 'none':
            args.extend(['-display', 'none'])
            args.append('-nographic')
        elif config.display == 'vnc':
            port = config.vnc_port or 5900
            args.extend(['-vnc', f':{port - 5900}'])
        elif config.display == 'gtk':
            args.extend(['-display', 'gtk'])
        
        return args
    
    def _generate_device_args(self, config: VMConfig) -> List[str]:
        """Generate device emulation arguments"""
        args = []
        
        # USB controller and devices
        args.extend(['-device', 'qemu-xhci,id=xhci'])
        args.extend(['-device', 'usb-kbd,id=kbd0'])
        args.extend(['-device', 'usb-mouse,id=mouse0'])
        
        # Audio (Intel HDA)
        args.extend([
            '-device', 'intel-hda',
            '-device', 'hda-duplex'
        ])
        
        # RNG device (looks realistic)
        args.extend(['-device', 'virtio-rng-pci'])
        
        return args
    
    def _generate_communication_args(self, config: VMConfig) -> List[str]:
        """Generate QMP monitor and serial communication arguments"""
        args = []
        
        sockets = config.get_socket_paths(self.sockets_dir)
        
        # QMP monitor for VM control
        args.extend([
            '-qmp', f"unix:{sockets['monitor']},server,nowait"
        ])
        
        # Serial port for communication with guest agent
        args.extend([
            '-chardev', f"socket,id=serial0,path={sockets['serial']},server=on,wait=off",
            '-serial', 'chardev:serial0'
        ])
        
        # Virtio-serial for guest agent
        args.extend([
            '-device', 'virtio-serial-pci',
            '-chardev', f"socket,id=agent0,path={sockets['agent']},server=on,wait=off",
            '-device', 'virtserialport,chardev=agent0,name=org.sandbox.agent'
        ])
        
        return args
    
    def _generate_firmware_args(self, config: VMConfig) -> List[str]:
        """Generate firmware arguments (UEFI for ARM64)"""
        args = []
        
        if config.architecture == VMArchitecture.ARM64:
            # UEFI firmware paths (common locations)
            uefi_paths = [
                '/usr/share/AAVMF/AAVMF_CODE.fd',
                '/usr/share/qemu-efi-aarch64/QEMU_EFI.fd',
                '/usr/share/edk2/aarch64/QEMU_EFI.fd',
            ]
            
            for path in uefi_paths:
                if os.path.exists(path):
                    args.extend(['-bios', path])
                    break
        
        return args
    
    def build_command(self, config: VMConfig, anti_vm: AntiVMConfig) -> List[str]:
        """Build complete QEMU command with all arguments"""
        args = []
        
        args.extend(self._generate_base_args(config))
        args.extend(self._generate_firmware_args(config))
        args.extend(self._generate_cpu_args(config, anti_vm))
        args.extend(self._generate_smbios_args(anti_vm))
        args.extend(self._generate_storage_args(config, anti_vm))
        args.extend(self._generate_network_args(config, anti_vm))
        args.extend(self._generate_display_args(config))
        args.extend(self._generate_device_args(config))
        args.extend(self._generate_communication_args(config))
        
        # Daemon mode
        args.append('-daemonize')
        
        return args
    
    def launch(self, config: VMConfig, anti_vm: AntiVMConfig) -> QEMUProcess:
        """Launch a new QEMU VM"""
        
        if not self._check_qemu_available(config.qemu_binary):
            raise RuntimeError(f"QEMU binary not found: {config.qemu_binary}")
        
        if not os.path.exists(config.image_path):
            raise FileNotFoundError(f"VM image not found: {config.image_path}")
        
        # Build command
        cmd = self.build_command(config, anti_vm)
        
        logger.info(f"Launching VM: {config.name}")
        logger.debug(f"QEMU command: {' '.join(cmd)}")
        
        # Get socket paths
        sockets = config.get_socket_paths(self.sockets_dir)
        
        # Clean up old sockets
        for sock_path in sockets.values():
            if os.path.exists(sock_path):
                os.unlink(sock_path)
        
        # Launch QEMU (daemonized)
        try:
            # Remove -daemonize for subprocess management
            cmd_no_daemon = [arg for arg in cmd if arg != '-daemonize']
            
            process = subprocess.Popen(
                cmd_no_daemon,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )
            
            # Wait for monitor socket to be created
            start_time = time.time()
            while time.time() - start_time < config.boot_timeout:
                if os.path.exists(sockets['monitor']):
                    break
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    raise RuntimeError(f"QEMU exited: {stderr.decode()}")
                time.sleep(0.1)
            else:
                process.kill()
                raise TimeoutError("QEMU monitor socket not created")
            
            qemu_proc = QEMUProcess(
                process=process,
                config=config,
                monitor_socket=sockets['monitor'],
                serial_socket=sockets['serial'],
                pid=process.pid,
            )
            
            self._processes[config.name] = qemu_proc
            logger.info(f"VM {config.name} started with PID {process.pid}")
            
            return qemu_proc
            
        except Exception as e:
            logger.error(f"Failed to launch VM: {e}")
            raise
    
    def stop(self, vm_name: str, force: bool = False):
        """Stop a running VM"""
        if vm_name not in self._processes:
            return
        
        proc = self._processes[vm_name]
        
        if force:
            proc.process.kill()
        else:
            # Send ACPI shutdown via QMP
            try:
                self._send_qmp_command(proc.monitor_socket, {'execute': 'system_powerdown'})
                proc.process.wait(timeout=10)
            except Exception:
                proc.process.kill()
        
        proc.process.wait()
        del self._processes[vm_name]
        
        # Clean up sockets
        sockets = proc.config.get_socket_paths(self.sockets_dir)
        for sock_path in sockets.values():
            if os.path.exists(sock_path):
                os.unlink(sock_path)
        
        logger.info(f"VM {vm_name} stopped")
    
    def stop_all(self):
        """Stop all running VMs"""
        for vm_name in list(self._processes.keys()):
            self.stop(vm_name, force=True)
    
    def _send_qmp_command(self, socket_path: str, command: Dict[str, Any]) -> Dict[str, Any]:
        """Send a QMP command to QEMU"""
        import json
        
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(socket_path)
            sock.settimeout(5.0)
            
            # Read greeting
            sock.recv(4096)
            
            # Send capabilities negotiation
            sock.send(b'{"execute": "qmp_capabilities"}\n')
            sock.recv(4096)
            
            # Send command
            sock.send((json.dumps(command) + '\n').encode())
            response = sock.recv(4096)
            
            return json.loads(response.decode())
        finally:
            sock.close()
    
    def get_process(self, vm_name: str) -> Optional[QEMUProcess]:
        """Get a running VM process"""
        return self._processes.get(vm_name)
    
    def is_running(self, vm_name: str) -> bool:
        """Check if a VM is running"""
        proc = self._processes.get(vm_name)
        return proc is not None and proc.is_running()
