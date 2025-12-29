#!/usr/bin/env python3
"""Test GPU access via Metal (macOS)"""

import sys

def test_metal():
    """Test Metal GPU access"""
    try:
        import Metal
        devices = Metal.MTLCopyAllDevices()
        if devices:
            print(f"Found {len(devices)} Metal device(s):")
            for i, device in enumerate(devices):
                print(f"  [{i}] {device.name()}")
            return True
        else:
            print("No Metal devices found")
            return False
    except ImportError:
        print("Metal module not available (pyobjc-framework-Metal not installed)")
        return None
    except Exception as e:
        print(f"Metal access denied or failed: {e}")
        return False

def test_opencl():
    """Test OpenCL GPU access"""
    try:
        import pyopencl as cl
        platforms = cl.get_platforms()
        if platforms:
            print(f"Found {len(platforms)} OpenCL platform(s):")
            for platform in platforms:
                print(f"  Platform: {platform.name}")
                devices = platform.get_devices()
                for device in devices:
                    print(f"    Device: {device.name}")
            return True
        else:
            print("No OpenCL platforms found")
            return False
    except ImportError:
        print("pyopencl not installed")
        return None
    except Exception as e:
        print(f"OpenCL access denied or failed: {e}")
        return False

if __name__ == "__main__":
    print("=== GPU Access Test ===\n")

    print("Testing Metal...")
    metal_result = test_metal()

    print("\nTesting OpenCL...")
    opencl_result = test_opencl()

    print("\n=== Results ===")
    print(f"Metal: {'OK' if metal_result else 'DENIED' if metal_result is False else 'N/A'}")
    print(f"OpenCL: {'OK' if opencl_result else 'DENIED' if opencl_result is False else 'N/A'}")

    # Exit with error if access was denied (not just unavailable)
    if metal_result is False or opencl_result is False:
        sys.exit(1)
