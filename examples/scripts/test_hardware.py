#!/usr/bin/env python3
"""Test general hardware access (USB, Bluetooth, cameras, etc.)"""

import sys

SYSTEM_PROFILER = "/usr/sbin/system_profiler"

def test_usb():
    """Test USB device enumeration"""
    try:
        import subprocess
        result = subprocess.run(
            [SYSTEM_PROFILER, "SPUSBDataType"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            lines = [l for l in result.stdout.split('\n') if l.strip()]
            print(f"USB profiler returned {len(lines)} lines")
            return True
        else:
            print(f"USB profiler failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"USB access failed: {e}")
        return False

def test_bluetooth():
    """Test Bluetooth device enumeration"""
    try:
        import subprocess
        result = subprocess.run(
            ["system_profiler", "SPBluetoothDataType"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            lines = [l for l in result.stdout.split('\n') if l.strip()]
            print(f"Bluetooth profiler returned {len(lines)} lines")
            return True
        else:
            print(f"Bluetooth profiler failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"Bluetooth access failed: {e}")
        return False

def test_camera():
    """Test camera device access"""
    try:
        import subprocess
        result = subprocess.run(
            ["system_profiler", "SPCameraDataType"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            if "No video capture devices" in result.stdout:
                print("No cameras found")
            else:
                lines = [l for l in result.stdout.split('\n') if l.strip()]
                print(f"Camera profiler returned {len(lines)} lines")
            return True
        else:
            print(f"Camera profiler failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"Camera access failed: {e}")
        return False

def test_audio():
    """Test audio device access"""
    try:
        import subprocess
        result = subprocess.run(
            ["system_profiler", "SPAudioDataType"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            lines = [l for l in result.stdout.split('\n') if l.strip()]
            print(f"Audio profiler returned {len(lines)} lines")
            return True
        else:
            print(f"Audio profiler failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"Audio access failed: {e}")
        return False

if __name__ == "__main__":
    print("=== Hardware Access Test ===\n")

    print("Testing USB...")
    usb_result = test_usb()

    print("\nTesting Bluetooth...")
    bt_result = test_bluetooth()

    print("\nTesting Camera...")
    cam_result = test_camera()

    print("\nTesting Audio...")
    audio_result = test_audio()

    print("\n=== Results ===")
    print(f"USB: {'OK' if usb_result else 'DENIED'}")
    print(f"Bluetooth: {'OK' if bt_result else 'DENIED'}")
    print(f"Camera: {'OK' if cam_result else 'DENIED'}")
    print(f"Audio: {'OK' if audio_result else 'DENIED'}")

    if not all([usb_result, bt_result, cam_result, audio_result]):
        sys.exit(1)
