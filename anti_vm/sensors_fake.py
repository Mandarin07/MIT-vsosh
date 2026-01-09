"""
Fake Hardware Sensors - Thermal zones, fans, battery, etc.

Real physical machines have various hardware sensors that VMs typically lack:
- Thermal zones (CPU temperature, chassis temperature)
- Fan speeds (CPU fan, system fans)
- Battery status (for laptops)
- ACPI sensors
- IPMI sensors

This module generates fake sensor data to make the VM look like real hardware.
"""

import os
import random
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ThermalZone:
    """Thermal zone configuration"""
    name: str = "x86_pkg_temp"
    base_temp: int = 45  # Celsius
    variance: int = 10  # Max variance
    policy: str = "step_wise"
    
    def get_temp(self) -> int:
        """Get current temperature in millidegrees"""
        temp = self.base_temp + random.randint(-self.variance // 2, self.variance)
        return temp * 1000  # Convert to millidegrees


@dataclass
class FanSensor:
    """Fan sensor configuration"""
    name: str = "dell_smm"
    label: str = "CPU Fan"
    base_rpm: int = 2400
    variance: int = 400
    max_rpm: int = 5000
    
    def get_rpm(self) -> int:
        """Get current fan speed"""
        return self.base_rpm + random.randint(-self.variance // 2, self.variance)


@dataclass
class BatteryInfo:
    """Battery information for laptop emulation"""
    manufacturer: str = "Dell"
    model_name: str = "DELL 7VTMR"
    technology: str = "Li-ion"
    capacity_percent: int = 67
    status: str = "Discharging"
    energy_full: int = 48000000  # microWh
    voltage_now: int = 11400000  # microV
    
    def get_energy_now(self) -> int:
        """Get current energy level"""
        return int(self.energy_full * self.capacity_percent / 100)


@dataclass
class SensorsConfig:
    """Complete sensors configuration"""
    
    # Thermal zones
    thermal_zones: List[ThermalZone] = field(default_factory=lambda: [
        ThermalZone(name="x86_pkg_temp", base_temp=47),
        ThermalZone(name="acpitz", base_temp=42),
    ])
    
    # Fan sensors
    fans: List[FanSensor] = field(default_factory=lambda: [
        FanSensor(name="dell_smm", label="CPU Fan", base_rpm=2400),
        FanSensor(name="dell_smm", label="System Fan", base_rpm=1800),
    ])
    
    # Battery (None for desktop)
    battery: Optional[BatteryInfo] = None
    
    # AC adapter
    ac_online: bool = True


class SensorsFaker:
    """
    Generates fake sensor data for sysfs.
    
    This class creates the directory structure and files that would
    exist on a real system with hardware monitoring support.
    """
    
    def __init__(self, config: Optional[SensorsConfig] = None):
        self.config = config or SensorsConfig()
    
    def create_fake_sysfs(self, base_path: str = "/opt/anti_vm/fake_sysfs"):
        """
        Create fake sysfs structure with sensor data.
        
        Args:
            base_path: Base directory for fake sysfs
        """
        base = Path(base_path)
        
        # Create directory structure
        dirs = [
            "class/thermal",
            "class/hwmon",
            "class/power_supply",
            "devices/virtual/input",
        ]
        
        for d in dirs:
            (base / d).mkdir(parents=True, exist_ok=True)
        
        # Create thermal zones
        self._create_thermal_zones(base)
        
        # Create hwmon entries
        self._create_hwmon(base)
        
        # Create power supply entries
        self._create_power_supply(base)
        
        # Create input devices
        self._create_input_devices(base)
    
    def _create_thermal_zones(self, base: Path):
        """Create thermal zone entries"""
        thermal_base = base / "class/thermal"
        
        for i, tz in enumerate(self.config.thermal_zones):
            zone_dir = thermal_base / f"thermal_zone{i}"
            zone_dir.mkdir(exist_ok=True)
            
            # Temperature
            (zone_dir / "temp").write_text(str(tz.get_temp()))
            
            # Type
            (zone_dir / "type").write_text(tz.name)
            
            # Policy
            (zone_dir / "policy").write_text(tz.policy)
            
            # Mode
            (zone_dir / "mode").write_text("enabled")
            
            # Trip points (cooling thresholds)
            for j, temp in enumerate([60000, 75000, 90000]):
                (zone_dir / f"trip_point_{j}_temp").write_text(str(temp))
                (zone_dir / f"trip_point_{j}_type").write_text(
                    ["passive", "active", "critical"][j]
                )
    
    def _create_hwmon(self, base: Path):
        """Create hardware monitoring entries"""
        hwmon_base = base / "class/hwmon"
        
        # Temperature sensors (coretemp-like)
        hwmon0 = hwmon_base / "hwmon0"
        hwmon0.mkdir(exist_ok=True)
        
        (hwmon0 / "name").write_text("coretemp")
        
        for i in range(4):  # 4 CPU cores
            temp = 45000 + random.randint(-3000, 5000)
            (hwmon0 / f"temp{i+1}_input").write_text(str(temp))
            (hwmon0 / f"temp{i+1}_label").write_text(f"Core {i}")
            (hwmon0 / f"temp{i+1}_max").write_text("100000")
            (hwmon0 / f"temp{i+1}_crit").write_text("110000")
        
        # Fan sensors
        hwmon1 = hwmon_base / "hwmon1"
        hwmon1.mkdir(exist_ok=True)
        
        (hwmon1 / "name").write_text("dell_smm")
        
        for i, fan in enumerate(self.config.fans):
            (hwmon1 / f"fan{i+1}_input").write_text(str(fan.get_rpm()))
            (hwmon1 / f"fan{i+1}_label").write_text(fan.label)
            (hwmon1 / f"fan{i+1}_max").write_text(str(fan.max_rpm))
        
        # Additional hwmon for motherboard sensors
        hwmon2 = hwmon_base / "hwmon2"
        hwmon2.mkdir(exist_ok=True)
        
        (hwmon2 / "name").write_text("nct6775")  # Common Nuvoton chip
        
        # Various temps
        for i, (label, temp) in enumerate([
            ("SYSTIN", 35000),
            ("CPUTIN", 45000),
            ("AUXTIN0", 30000),
            ("AUXTIN1", 28000),
            ("AUXTIN2", 27000),
        ]):
            (hwmon2 / f"temp{i+1}_input").write_text(str(temp + random.randint(-2000, 2000)))
            (hwmon2 / f"temp{i+1}_label").write_text(label)
        
        # Voltages
        for i, (label, mv) in enumerate([
            ("Vcore", 1100),
            ("in1", 1000),
            ("+3.3V", 3312),
            ("+5V", 5040),
            ("+12V", 12096),
        ]):
            (hwmon2 / f"in{i}_input").write_text(str(mv + random.randint(-20, 20)))
            (hwmon2 / f"in{i}_label").write_text(label)
    
    def _create_power_supply(self, base: Path):
        """Create power supply entries"""
        ps_base = base / "class/power_supply"
        
        # AC adapter
        ac_dir = ps_base / "AC"
        ac_dir.mkdir(exist_ok=True)
        
        (ac_dir / "type").write_text("Mains")
        (ac_dir / "online").write_text("1" if self.config.ac_online else "0")
        
        # Battery (if configured)
        if self.config.battery:
            bat = self.config.battery
            bat_dir = ps_base / "BAT0"
            bat_dir.mkdir(exist_ok=True)
            
            (bat_dir / "type").write_text("Battery")
            (bat_dir / "status").write_text(bat.status)
            (bat_dir / "present").write_text("1")
            (bat_dir / "technology").write_text(bat.technology)
            (bat_dir / "capacity").write_text(str(bat.capacity_percent))
            (bat_dir / "capacity_level").write_text("Normal")
            (bat_dir / "manufacturer").write_text(bat.manufacturer)
            (bat_dir / "model_name").write_text(bat.model_name)
            (bat_dir / "energy_full").write_text(str(bat.energy_full))
            (bat_dir / "energy_now").write_text(str(bat.get_energy_now()))
            (bat_dir / "energy_full_design").write_text(str(bat.energy_full))
            (bat_dir / "voltage_now").write_text(str(bat.voltage_now))
            (bat_dir / "voltage_min_design").write_text("10800000")
    
    def _create_input_devices(self, base: Path):
        """Create input device entries"""
        input_base = base / "devices/virtual/input"
        
        # Keyboard
        kbd_dir = input_base / "input0"
        kbd_dir.mkdir(exist_ok=True)
        (kbd_dir / "name").write_text("AT Translated Set 2 keyboard")
        (kbd_dir / "phys").write_text("isa0060/serio0/input0")
        
        # Mouse
        mouse_dir = input_base / "input1"
        mouse_dir.mkdir(exist_ok=True)
        (mouse_dir / "name").write_text("Logitech USB Receiver")
        (mouse_dir / "phys").write_text("usb-0000:00:14.0-1/input0")
        
        # Create mice symlink target
        (input_base / "mice").touch()
    
    def generate_update_script(self) -> str:
        """
        Generate a script that updates sensor values periodically.
        
        This makes the sensor values change over time, which is more realistic
        than static values.
        """
        script = '''#!/bin/bash
# Update fake sensor values periodically

SYSFS_BASE="${1:-/opt/anti_vm/fake_sysfs}"

update_sensors() {
    # Update thermal zones
    for zone in "$SYSFS_BASE"/class/thermal/thermal_zone*/temp; do
        if [ -f "$zone" ]; then
            base=$(cat "$zone")
            base=${base:-45000}
            variance=$((RANDOM % 3000 - 1500))
            new_temp=$((base + variance))
            # Keep in reasonable range
            [ $new_temp -lt 35000 ] && new_temp=35000
            [ $new_temp -gt 75000 ] && new_temp=75000
            echo $new_temp > "$zone" 2>/dev/null
        fi
    done
    
    # Update fan speeds
    for fan in "$SYSFS_BASE"/class/hwmon/hwmon*/fan*_input; do
        if [ -f "$fan" ]; then
            base=$(cat "$fan")
            base=${base:-2400}
            variance=$((RANDOM % 200 - 100))
            new_rpm=$((base + variance))
            [ $new_rpm -lt 1000 ] && new_rpm=1000
            [ $new_rpm -gt 5000 ] && new_rpm=5000
            echo $new_rpm > "$fan" 2>/dev/null
        fi
    done
    
    # Update CPU temps
    for temp in "$SYSFS_BASE"/class/hwmon/hwmon0/temp*_input; do
        if [ -f "$temp" ]; then
            base=$(cat "$temp")
            base=${base:-45000}
            variance=$((RANDOM % 2000 - 1000))
            new_temp=$((base + variance))
            [ $new_temp -lt 35000 ] && new_temp=35000
            [ $new_temp -gt 85000 ] && new_temp=85000
            echo $new_temp > "$temp" 2>/dev/null
        fi
    done
    
    # Update battery if present
    bat_now="$SYSFS_BASE/class/power_supply/BAT0/energy_now"
    if [ -f "$bat_now" ]; then
        current=$(cat "$bat_now")
        # Slowly decrease (discharging)
        new_val=$((current - 10000))
        [ $new_val -lt 0 ] && new_val=0
        echo $new_val > "$bat_now" 2>/dev/null
        
        # Update capacity
        full="$SYSFS_BASE/class/power_supply/BAT0/energy_full"
        if [ -f "$full" ]; then
            full_val=$(cat "$full")
            capacity=$((new_val * 100 / full_val))
            echo $capacity > "$SYSFS_BASE/class/power_supply/BAT0/capacity" 2>/dev/null
        fi
    fi
}

# Run update loop
while true; do
    update_sensors
    sleep 30
done
'''
        return script
    
    def get_mount_commands(self) -> List[str]:
        """
        Get commands to mount fake sysfs over real sysfs.
        
        These commands should be run at boot with appropriate privileges.
        """
        base = "/opt/anti_vm/fake_sysfs"
        commands = []
        
        # Mount thermal zones
        for i in range(len(self.config.thermal_zones)):
            src = f"{base}/class/thermal/thermal_zone{i}"
            dst = f"/sys/class/thermal/thermal_zone{i}"
            commands.append(f"mount --bind {src} {dst} 2>/dev/null || true")
        
        # Mount hwmon
        for i in range(3):
            src = f"{base}/class/hwmon/hwmon{i}"
            dst = f"/sys/class/hwmon/hwmon{i}"
            commands.append(f"mount --bind {src} {dst} 2>/dev/null || true")
        
        # Mount power supply
        commands.append(f"mount --bind {base}/class/power_supply/AC /sys/class/power_supply/AC 2>/dev/null || true")
        
        if self.config.battery:
            commands.append(f"mount --bind {base}/class/power_supply/BAT0 /sys/class/power_supply/BAT0 2>/dev/null || true")
        
        return commands


def create_desktop_sensors() -> SensorsFaker:
    """Create sensors configuration for a desktop system"""
    config = SensorsConfig(
        thermal_zones=[
            ThermalZone(name="x86_pkg_temp", base_temp=47),
            ThermalZone(name="acpitz", base_temp=42),
        ],
        fans=[
            FanSensor(label="CPU Fan", base_rpm=2400),
            FanSensor(label="System Fan", base_rpm=1800),
            FanSensor(label="Chassis Fan", base_rpm=1500),
        ],
        battery=None,
        ac_online=True,
    )
    return SensorsFaker(config)


def create_laptop_sensors() -> SensorsFaker:
    """Create sensors configuration for a laptop system"""
    config = SensorsConfig(
        thermal_zones=[
            ThermalZone(name="x86_pkg_temp", base_temp=52),
            ThermalZone(name="acpitz", base_temp=45),
            ThermalZone(name="pch_skylake", base_temp=48),
        ],
        fans=[
            FanSensor(label="CPU Fan", base_rpm=3200),
        ],
        battery=BatteryInfo(
            manufacturer="Dell",
            model_name="DELL 7VTMR",
            capacity_percent=67,
            status="Discharging",
        ),
        ac_online=False,
    )
    return SensorsFaker(config)
