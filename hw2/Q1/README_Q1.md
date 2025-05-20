# Lattice-Based Access Control System
A Python implementation of a lattice-based mandatory access control (MAC) system using security labels with three predefined categories: "ADMIN", "LECTURERS", and "STUDENTS".

## How to Run and Test

1. Save the implementation as `lattice_mac.py`
2. Save the test cases as `test_cases.py`
3. Run the tests with: `python test_cases.py` or `python3 python test_cases.py`

## Usage Example

```python
from lattice_mac import SecurityLabel, Subject, Object, can_access

# Define a student and a document
student = Subject("Student", SecurityLabel({"STUDENTS"}))
document = Object("Document", SecurityLabel({"STUDENTS", "LECTURERS"}))

# Check access
if can_access(student, document):
 print("Access granted")  # This will print
else:
 print("Access denied")
```
