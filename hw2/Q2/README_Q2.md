# Capability-Based Access Control with Multi-Ownership
This project implements a capability-based access control system in Python, with support for multiple owners per object.

**Key components**:
- **Subjects** (users) have capabilities that grant them specific rights on objects
- **Objects** can have multiple owners (subjects with the 'own' right)
- Only owners can modify the capabilities of subjects on an object
- Rights include: _read_, _write_, _own_.

## Running the Tests
To run the test suite, run the following command:

```bash
python3 test_capabilities.py
```

## Assumptions
- Initial ownership must be manually established when objects are created
- The system maintains data in memory only (no persistence layer)
- No authentication mechanism is implemented
- The list of possible rights is unrestricted (any string can serve as a right)
- Capabilities are stored with subjects rather than in a central database
- Ownership is a special right that allows modifying other users' capabilities
- When a subject is granted the 'own' right, they are automatically added to the object's owner list
- When a subject's 'own' right is revoked, they are automatically removed from the object's owner list

## Design Explanation
The implementation follows the capability-based access control model where subjects hold capabilities that grant rights over objects. The key features are:

1. **Object-Subject Relationship**: Capabilities establish what operations a subject can perform on an object.
2. **Multiple Ownership**: Objects have a list of owners, which corresponds to subjects who have the "own" capability.
3. **Access Control Logic**: 
   - Only owners can modify (add/remove) capabilities of other subjects
   - When a subject receives the "own" capability, they're automatically added to the object's owner list
   - When the "own" capability is revoked, the subject is removed from the owner list

4. **Capability Management**:
   - Capabilities are added and removed with proper permission checks
   - Individual rights can be selectively granted or revoked
   - A subject's entire capability for an object can be removed at once

The test cases verify that the system properly enforces these access control rules across different scenarios, from basic permission management to the key multi-ownership features that make this implementation distinctive.
