# README\_Q3.md

This project implements a Role-Based Access Control (RBAC) system in Python with support for hierarchical roles.
Roles include Admin, Lecturer, TeachingAssistant, and Student, each with associated permissions such as 'create\_course', 'grade\_students', 'submit\_assignment', and 'view\_materials'. Role inheritance allows higher-level roles to access all permissions of lower-level roles.

Key components:

* `Permission`, `Role`, and `User` classes.
* Recursive role permission checking with inheritance.
* Sample users and test cases to validate the access control logic.

## How to run

1. Make sure `rbac_system.py` and `test_rbac.py` are in the same directory.
2. Run the test file using:

```bash
python test_rbac.py
```

This will display the results of the access checks for different users and permissions.
