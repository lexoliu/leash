#!/usr/bin/env python3
"""Test that security protections are working (these should fail in strict mode)"""

import os
import sys

def test_read_ssh():
    """Try to read SSH keys (should be denied)"""
    ssh_dir = os.path.expanduser("~/.ssh")
    try:
        if os.path.exists(ssh_dir):
            files = os.listdir(ssh_dir)
            print(f"SSH directory readable: {files}")
            return False  # Should have been denied!
        else:
            print("SSH directory does not exist")
            return None
    except PermissionError:
        print("SSH access denied (expected)")
        return True
    except Exception as e:
        print(f"SSH access error: {e}")
        return True  # Any error is acceptable

def test_read_aws():
    """Try to read AWS credentials (should be denied)"""
    aws_dir = os.path.expanduser("~/.aws")
    try:
        if os.path.exists(aws_dir):
            files = os.listdir(aws_dir)
            print(f"AWS directory readable: {files}")
            return False  # Should have been denied!
        else:
            print("AWS directory does not exist")
            return None
    except PermissionError:
        print("AWS access denied (expected)")
        return True
    except Exception as e:
        print(f"AWS access error: {e}")
        return True

def test_read_browser_data():
    """Try to read browser data (should be denied)"""
    chrome_dir = os.path.expanduser("~/Library/Application Support/Google/Chrome")
    try:
        if os.path.exists(chrome_dir):
            files = os.listdir(chrome_dir)
            print(f"Chrome directory readable: {files[:5]}...")
            return False  # Should have been denied!
        else:
            print("Chrome directory does not exist")
            return None
    except PermissionError:
        print("Chrome access denied (expected)")
        return True
    except Exception as e:
        print(f"Chrome access error: {e}")
        return True

def test_read_keychain():
    """Try to read keychain (should be denied)"""
    keychain_dir = os.path.expanduser("~/Library/Keychains")
    try:
        if os.path.exists(keychain_dir):
            files = os.listdir(keychain_dir)
            print(f"Keychain directory readable: {files}")
            return False  # Should have been denied!
        else:
            print("Keychain directory does not exist")
            return None
    except PermissionError:
        print("Keychain access denied (expected)")
        return True
    except Exception as e:
        print(f"Keychain access error: {e}")
        return True

if __name__ == "__main__":
    print("=== Security Protection Test ===")
    print("(All accesses should be DENIED in strict mode)\n")

    print("Testing SSH access...")
    ssh_result = test_read_ssh()

    print("\nTesting AWS access...")
    aws_result = test_read_aws()

    print("\nTesting browser data access...")
    browser_result = test_read_browser_data()

    print("\nTesting keychain access...")
    keychain_result = test_read_keychain()

    print("\n=== Results ===")
    results = {
        "SSH": ssh_result,
        "AWS": aws_result,
        "Browser": browser_result,
        "Keychain": keychain_result,
    }

    all_protected = True
    for name, result in results.items():
        if result is None:
            status = "N/A (not present)"
        elif result:
            status = "PROTECTED"
        else:
            status = "EXPOSED!"
            all_protected = False
        print(f"{name}: {status}")

    if not all_protected:
        print("\nWARNING: Some sensitive data is exposed!")
        sys.exit(1)
    else:
        print("\nAll sensitive data is protected.")
