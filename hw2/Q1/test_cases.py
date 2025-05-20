"""
CENG418 Assignment - 2 | Q1
    Damla Keleş     280201057
    Murat Küçük     280201052
    Yusuf Atmaca    270201084
"""

from lattice_mac import SecurityLabel, Subject, Object, can_access, can_read, can_write, display_lattice

def run_tests():
    # Define categories
    ADMIN = "ADMIN"
    LECTURERS = "LECTURERS"
    STUDENTS = "STUDENTS"
    
    # Create security labels
    empty_label = SecurityLabel()
    students_label = SecurityLabel({STUDENTS})
    lecturers_label = SecurityLabel({LECTURERS})
    students_lecturers_label = SecurityLabel({STUDENTS, LECTURERS})
    admin_label = SecurityLabel({ADMIN})
    all_access_label = SecurityLabel({ADMIN, LECTURERS, STUDENTS})
    
    # Create subjects
    empty_subject = Subject("Empty", empty_label)
    student = Subject("Student", students_label)
    lecturer = Subject("Lecturer", lecturers_label)
    student_lecturer = Subject("StudentLecturer", students_lecturers_label)
    admin = Subject("Admin", admin_label)
    super_admin = Subject("SuperAdmin", all_access_label)
    
    # Create objects
    empty_object = Object("EmptyObject", empty_label)
    student_object = Object("StudentObject", students_label)
    lecturer_object = Object("LecturerObject", lecturers_label)
    student_lecturer_object = Object("StudentLecturerObject", students_lecturers_label)
    admin_object = Object("AdminObject", admin_label)
    all_access_object = Object("AllAccessObject", all_access_label)
    
    # Test cases
    test_cases = [
        # Required test cases as specified in the assignment
        (student, student_object, True, "Test 1: Subject: {STUDENTS} vs. Object: {STUDENTS} → ✅Access"),
        (student, student_lecturer_object, True, "Test 2: Subject: {STUDENTS} vs. Object: {STUDENTS, LECTURERS} → ✅Access"),
        (student, lecturer_object, False, "Test 3: Subject: {STUDENTS} vs. Object: {LECTURERS} → ❌Denied"),
        (empty_subject, student_object, True, "Test 4: Subject: {} (empty set) vs. Object: {STUDENTS} → ✅Access"),
        (student, empty_object, False, "Test 5: Subject: {STUDENTS} vs. Object: {} → ❌Denied"),
    ]
    
    # Run the tests
    print("\nRunning access control tests:")
    print("=============================")
    for subject, obj, expected, description in test_cases:
        result = can_access(subject, obj)
        status = "✅" if result == expected else "❌"
        print(f"{status} {description}")
        print(f"   - Subject: {subject.name} with label {subject.label}")
        print(f"   - Object: {obj.name} with label {obj.label}")
        print(f"   - Access: {'Granted' if result else 'Denied'}\n")
    
    # Bonus: Test read/write distinction
    print("\nTesting read/write distinction:")
    print("==============================")
    
    read_write_tests = [
        (student, student_object, True, True, "Student can read and write StudentObject"),
        (student, student_lecturer_object, True, False, "Student can read but not write StudentLecturerObject"),
        (empty_subject, student_object, True, False, "Empty subject can read but not write StudentObject"),
    ]
    
    for subject, obj, expected_read, expected_write, description in read_write_tests:
        read_result = can_read(subject, obj)
        write_result = can_write(subject, obj)
        read_status = "✅" if read_result == expected_read else "❌"
        write_status = "✅" if write_result == expected_write else "❌"
        print(f"{description}")
        print(f"{read_status} Read: {'Allowed' if read_result else 'Denied'}")
        print(f"{write_status} Write: {'Allowed' if write_result else 'Denied'}\n")
    
    # Bonus: Display the lattice structure
    print("\nGenerating lattice structure:")
    print("===========================")
    categories = {ADMIN, LECTURERS, STUDENTS}
    display_lattice(categories)

if __name__ == "__main__":
    run_tests()
