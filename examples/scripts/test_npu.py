#!/usr/bin/env python3
"""Test NPU/Neural Engine access via CoreML (macOS)"""

import sys

def test_coreml():
    """Test CoreML Neural Engine access"""
    try:
        import coremltools as ct
        print(f"CoreML Tools version: {ct.__version__}")
        print("CoreML import successful")
        return True
    except ImportError:
        print("coremltools not installed")
        return None
    except Exception as e:
        print(f"CoreML access failed: {e}")
        return False

def test_ane_availability():
    """Check if Apple Neural Engine is available"""
    try:
        import subprocess
        result = subprocess.run(
            ["system_profiler", "SPHardwareDataType"],
            capture_output=True,
            text=True
        )
        if "Apple M" in result.stdout:
            print("Apple Silicon detected - Neural Engine available")
            return True
        else:
            print("Intel Mac - Neural Engine not available")
            return None
    except Exception as e:
        print(f"Hardware check failed: {e}")
        return False

def test_mlx():
    """Test MLX framework (Apple Silicon ML)"""
    try:
        import mlx.core as mx
        print(f"MLX available")
        # Simple operation to verify GPU/NPU access
        a = mx.array([1, 2, 3])
        b = mx.array([4, 5, 6])
        c = a + b
        mx.eval(c)
        print(f"MLX computation: {a.tolist()} + {b.tolist()} = {c.tolist()}")
        return True
    except ImportError:
        print("mlx not installed")
        return None
    except Exception as e:
        print(f"MLX access denied or failed: {e}")
        return False

if __name__ == "__main__":
    print("=== NPU/Neural Engine Access Test ===\n")

    print("Checking hardware...")
    ane_result = test_ane_availability()

    print("\nTesting CoreML...")
    coreml_result = test_coreml()

    print("\nTesting MLX...")
    mlx_result = test_mlx()

    print("\n=== Results ===")
    print(f"Neural Engine: {'Available' if ane_result else 'N/A' if ane_result is None else 'Check Failed'}")
    print(f"CoreML: {'OK' if coreml_result else 'DENIED' if coreml_result is False else 'N/A'}")
    print(f"MLX: {'OK' if mlx_result else 'DENIED' if mlx_result is False else 'N/A'}")

    if coreml_result is False or mlx_result is False:
        sys.exit(1)
