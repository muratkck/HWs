"""
CENG418 Assignment - 2 | Q2
    Damla Keleş     280201057
    Murat Küçük     280201052
    Yusuf Atmaca    270201084
"""

import unittest
from capability_system import Subject, Object, Capability, add_capability, remove_capability, check_access, get_owners

class TestCapabilitySystem(unittest.TestCase):
    
    def setUp(self):
        print("\n=== Setting up test environment ===")
        
        # Create subjects
        self.alice = Subject("Alice")
        self.bob = Subject("Bob")
        self.charlie = Subject("Charlie")
        self.dave = Subject("Dave")
        self.eve = Subject("Eve")
        print(f"Created subjects: Alice, Bob, Charlie, Dave, Eve")
        
        # Create objects
        self.file1 = Object("File1")
        self.file2 = Object("File2")
        print(f"Created objects: File1, File2")
        
        # Single Owner Modification
        # _Alice_ owns `File1`
        self.file1.owners.append(self.alice)
        capability = Capability(self.file1, ["own", "read", "write"])
        self.alice.capabilities.append(capability)
        print(f"Set up Alice as the owner of File1 with read/write permissions")
        
        # Multiple Ownership
        # _Alice_ and _Bob_ own `File2`
        self.file2.owners.extend([self.alice, self.bob])
        capability_alice = Capability(self.file2, ["own", "read", "write"])
        capability_bob = Capability(self.file2, ["own", "read", "write"])
        self.alice.capabilities.append(capability_alice)
        self.bob.capabilities.append(capability_bob)
        print(f"Set up both Alice and Bob as co-owners of File2 with read/write permissions")


    def test_single_owner_modification(self):
        """
        _Alice_ owns `File1`.
        _Alice_ gives _Bob_ _read_ and _write_ on `File1`.
        _Bob_ can _read_ and _write_, but not grant access to Charlie.
        """
        
        print("\n=== TEST: Single Owner Modification ===")
        print("Scenario: Alice owns File1 and gives Bob read/write access. Bob cannot grant access to Charlie.")
        
        # _Alice_ gives _Bob_ _read_ and _write_ on `File1`
        print("Alice grants Bob read and write access to File1")
        add_capability(self.alice, self.bob, self.file1, ["read", "write"])
        
        # Check that _Bob_ has _read_ and _write_ access
        if check_access(self.bob, self.file1, "read") and check_access(self.bob, self.file1, "write"):
            print("✓ Verified: Bob now has read and write access to File1")
        
        # Check that _Bob_ cannot modify _Charlie's_ access (doesn't have _own_)
        print("Bob attempts to give Charlie read access to File1 (should fail because Bob is not an owner)")
        try:
            add_capability(self.bob, self.charlie, self.file1, ["read"])
            print("✗ ERROR: Bob was able to modify permissions without ownership")
        except PermissionError as e:
            print(f"✓ Verified: Permission denied as expected - {e}")
    
    def test_multiple_ownership(self):
        """
        _Alice_ and _Bob_ both own `File2`.
        _Either_ can independently grant _Charlie_ access.
        """
        
        print("\n=== TEST: Multiple Ownership ===")
        print("Scenario: Alice and Bob both own File2 and can independently grant Charlie access.")
        
        # _Alice_ grants _Charlie_ _read_ access
        print("Alice grants Charlie read access to File2")
        add_capability(self.alice, self.charlie, self.file2, ["read"])
        if check_access(self.charlie, self.file2, "read"):
            print("✓ Verified: Charlie now has read access to File2")
        
        # _Bob_ grants _Charlie_ _write_ access
        print("Bob grants Charlie write access to File2")
        add_capability(self.bob, self.charlie, self.file2, ["write"])
        if check_access(self.charlie, self.file2, "write"):
            print("✓ Verified: Charlie now has write access to File2")
        print("This demonstrates that multiple owners can independently manage permissions")
    
    def test_unauthorized_modification(self):
        """
        _Dave_ tries to grant _Eve_ access to `File1` without being an _owner_.
        Raise an error.
        """
        
        print("\n=== TEST: Unauthorized Modification ===")
        print("Scenario: Dave tries to grant Eve access to File1 without being an owner.")
        
        print("Dave attempts to give Eve read access to File1 (should fail)")
        try:
            add_capability(self.dave, self.eve, self.file1, ["read"])
            print("✗ ERROR: Dave was able to modify permissions without ownership")
        except PermissionError as e:
            print(f"✓ Verified: Permission denied as expected - {e}")
    
    def test_revocation_scenario(self):
        """
        _Alice_ revokes _Charlie's_ write access to `File2`.
        _Charlie_ can no longer _write_ but may still _read_ (if that wasn't removed).
        """
        
        print("\n=== TEST: Revocation Scenario ===")
        print("Scenario: Alice revokes Charlie's write access to File2, but Charlie retains read access.")
        
        
        # First, give Charlie both read and write
        print("Alice grants Charlie both read and write access to File2")
        add_capability(self.alice, self.charlie, self.file2, ["read", "write"])
        if check_access(self.charlie, self.file2, "read") and check_access(self.charlie, self.file2, "write"):
            print("✓ Verified: Charlie now has both read and write access to File2")
        
        # _Alice_ revokes _write_ access
        print("Alice revokes Charlie's write access to File2")
        remove_capability(self.alice, self.charlie, self.file2, ["write"])
        charlie_caps = [cap.rights for cap in self.charlie.capabilities if cap.object == self.file2]
        print(f"Charlie's current rights on File2: {charlie_caps}")
        
        if check_access(self.charlie, self.file2, "read"):
            print("✓ Verified: Charlie still has read access to File2")
        else:
            print("✗ ERROR: Charlie lost read access when only write should have been removed")
            
        if not check_access(self.charlie, self.file2, "write"):
            print("✓ Verified: Charlie no longer has write access to File2")
        else:
            print("✗ ERROR: Charlie still has write access when it should have been removed")
    
    def test_ownership_removal(self):
        """
        _Alice_ removes _Bob's_ own right on `File2`.
        _Bob_ can no longer modify others' capabilities on `File2`.
        """
        
        print("\n=== TEST: Ownership Removal ===")
        print("Scenario: Alice removes Bob's ownership of File2. Bob can no longer modify permissions.")
        
        
        # Verify _Bob_ is initially an owner
        if self.bob in get_owners(self.file2):
            print("✓ Verified: Bob is initially an owner of File2")
        
        # _Alice_ removes _Bob's_ ownership
        print("Alice revokes Bob's ownership rights on File2")
        remove_capability(self.alice, self.bob, self.file2, ["own"])
        
        # _Bob_ is no longer an owner
        if self.bob not in get_owners(self.file2):
            print("✓ Verified: Bob is no longer an owner of File2")
        
        # _Bob_ can't modify _Charlie's_ access anymore
        print("Bob attempts to give Charlie read access to File2 (should fail now)")
        try:
            add_capability(self.bob, self.charlie, self.file2, ["read"])
            print("✗ ERROR: Bob was able to modify permissions after ownership was revoked")
        except PermissionError as e:
            print(f"✓ Verified: Permission denied as expected - {e}")

if __name__ == "__main__":
    unittest.main()
