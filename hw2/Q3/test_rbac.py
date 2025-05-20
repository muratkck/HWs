# test_rbac.py
from rbac_system import Permission, Role, User, has_permission

# Define permissions
create_course = Permission('create_course')
grade_students = Permission('grade_students')
submit_assignment = Permission('submit_assignment')
view_materials = Permission('view_materials')

# Define role hierarchy
student_role = Role("Student", [submit_assignment, view_materials])
ta_role = Role("TeachingAssistant", [], parent=student_role)
lecturer_role = Role("Lecturer", [grade_students], parent=ta_role)
admin_role = Role("Admin", [create_course], parent=lecturer_role)

# Define users
student = User("alice", [student_role])
ta = User("bob", [ta_role])
lecturer = User("carol", [lecturer_role])
admin = User("dave", [admin_role])

# Test scenarios
print("Student views materials:", has_permission(student, 'view_materials'))  # ✅
print("TA grades students:", has_permission(ta, 'grade_students'))             # ❌
print("Lecturer grades students:", has_permission(lecturer, 'grade_students')) # ✅
print("Admin creates course:", has_permission(admin, 'create_course'))         # ✅
print("Student creates course:", has_permission(student, 'create_course'))     # ❌
