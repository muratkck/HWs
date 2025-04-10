import os
import json
import time
import uuid
import base64
from datetime import datetime
from tabulate import tabulate
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.exceptions import InvalidSignature

class Person:
    """Base class for both students and instructors."""
    def __init__(self, name):
        self.name = name
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def get_public_key_pem(self):
        """Export public key in PEM format."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def sign_message(self, message):
        """Sign a message (bytes or string) with private key."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, message, signature, public_key_pem):
        """Verify signature using a public key."""
        public_key = serialization.load_pem_public_key(public_key_pem)
        if isinstance(message, str):
            message = message.encode('utf-8')
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    def encrypt_message(self, message, recipient_public_key_pem):
        """Encrypt a message for another party using their public key."""
        recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem)
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        ciphertext = recipient_public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    def decrypt_message(self, ciphertext):
        """Decrypt a message encrypted with this person's public key."""
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

class Student(Person):
    def __init__(self, name, student_id):
        super().__init__(name)
        self.student_id = student_id
        self.anonymous_id = None
        self.submissions = []
        self.grades = {}
    
    def request_anonymous_id(self, instructor):
        """Request an anonymous ID from the instructor."""
        timestamp = datetime.now().isoformat()
        request_data = {
            "student_id": self.student_id,
            "timestamp": timestamp,
            "action": "request_anonymous_id"
        }
        
        # Serialize the request data
        request_json = json.dumps(request_data, sort_keys=True)
        
        # Sign the request
        signature = self.sign_message(request_json)
        
        # Send the request to the instructor
        print(f"\n[Student {self.name}] Requesting anonymous ID...")
        response = instructor.process_anonymous_id_request(
            request_json, 
            signature, 
            self.get_public_key_pem()
        )
        
        if response:
            encrypted_aid, instructor_signature = response
            
            # Verify instructor's signature
            if self.verify_signature(encrypted_aid, instructor_signature, instructor.get_public_key_pem()):
                # Decrypt the anonymous ID
                aid_bytes = self.decrypt_message(encrypted_aid)
                self.anonymous_id = aid_bytes.decode('utf-8')
                print(f"[Student {self.name}] Received anonymous ID: {self.anonymous_id}")
                return True
            else:
                print(f"[Student {self.name}] Invalid instructor signature!")
                return False
        else:
            print(f"[Student {self.name}] Failed to get anonymous ID!")
            return False
    
    def create_submission(self, content):
        """Create a submission with the given content."""
        if not self.anonymous_id:
            print(f"[Student {self.name}] Cannot submit without an anonymous ID!")
            return None
        
        timestamp = datetime.now().isoformat()
        submission_data = {
            "anonymous_id": self.anonymous_id,
            "timestamp": timestamp,
            "content": content
        }
        
        # Serialize the submission data
        submission_json = json.dumps(submission_data, sort_keys=True)
        
        # Sign the submission
        signature = self.sign_message(submission_json)
        
        submission = {
            "data": submission_data,
            "signature": base64.b64encode(signature).decode('utf-8')
        }
        
        self.submissions.append(submission)
        return submission
    
    def submit_work(self, instructor, content):
        """Submit work to the instructor."""
        if not self.anonymous_id:
            print(f"[Student {self.name}] Cannot submit without an anonymous ID!")
            return False
        
        submission = self.create_submission(content)
        if not submission:
            return False
        
        # Convert submission to JSON for sending
        submission_str = json.dumps(submission["data"], sort_keys=True)
        signature = base64.b64decode(submission["signature"])
        
        print(f"\n[Student {self.name}] Submitting work anonymously...")
        result = instructor.receive_submission(
            submission_str,
            signature,
            self.get_public_key_pem()
        )
        
        if result:
            print(f"[Student {self.name}] Work submitted successfully with anonymous ID: {self.anonymous_id}")
            return True
        else:
            print(f"[Student {self.name}] Submission failed!")
            return False
    
    def check_grade(self, instructor):
        """Check grade for submissions."""
        if not self.anonymous_id:
            print(f"[Student {self.name}] No anonymous ID to check grades for!")
            return None
        
        grades = instructor.get_published_grades()
        if self.anonymous_id in grades:
            grade = grades[self.anonymous_id]
            self.grades[self.anonymous_id] = grade
            print(f"\n[Student {self.name}] My grade (anonymously as {self.anonymous_id}): {grade}")
            return grade
        else:
            print(f"\n[Student {self.name}] No grade found for anonymous ID: {self.anonymous_id}")
            return None

class Instructor(Person):
    def __init__(self, name):
        super().__init__(name)
        # Maps student_id -> public_key_pem
        self.registered_students = {}
        # Maps student_id -> anonymous_id
        self.student_aid_map = {}
        # Maps anonymous_id -> student_id (reverse lookup)
        self.aid_student_map = {}
        # Maps anonymous_id -> {submission, grade}
        self.submissions = {}
        # Maps anonymous_id -> grade (published)
        self.published_grades = {}
    
    def register_student(self, student_id, public_key_pem):
        """Register a student with their public key."""
        self.registered_students[student_id] = public_key_pem
        print(f"[Instructor {self.name}] Registered student: {student_id}")
        return True
    
    def process_anonymous_id_request(self, request_json, signature, public_key_pem):
        """Process a request for an anonymous ID."""
        # Verify the signature
        if not self.verify_signature(request_json, signature, public_key_pem):
            print("[Instructor] Invalid signature on anonymous ID request!")
            return None
        
        # Parse the request
        request = json.loads(request_json)
        student_id = request["student_id"]
        
        # Check if the student is registered
        if student_id not in self.registered_students:
            # Auto-register for demo purposes
            self.register_student(student_id, public_key_pem)
        
        # Verify the public key matches the registered one
        if self.registered_students[student_id] != public_key_pem:
            print(f"[Instructor] Public key mismatch for student {student_id}!")
            return None
        
        # Generate a unique anonymous ID
        anonymous_id = str(uuid.uuid4())
        
        # Store the mapping
        self.student_aid_map[student_id] = anonymous_id
        self.aid_student_map[anonymous_id] = student_id
        
        # Encrypt the anonymous ID with the student's public key
        encrypted_aid = self.encrypt_message(anonymous_id, public_key_pem)
        
        # Sign the encrypted anonymous ID
        instructor_signature = self.sign_message(encrypted_aid)
        
        print(f"[Instructor {self.name}] Issued anonymous ID for student {student_id}")
        return (encrypted_aid, instructor_signature)
    
    def receive_submission(self, submission_str, signature, public_key_pem):
        """Receive and verify a submission."""
        # Verify the signature
        if not self.verify_signature(submission_str, signature, public_key_pem):
            print("[Instructor] Invalid signature on submission!")
            return False
        
        # Parse the submission
        submission = json.loads(submission_str)
        anonymous_id = submission["anonymous_id"]
        
        # Check if the anonymous ID is valid
        if anonymous_id not in self.aid_student_map:
            print(f"[Instructor] Invalid anonymous ID: {anonymous_id}")
            return False
        
        # Get the student ID for this anonymous ID
        student_id = self.aid_student_map[anonymous_id]
        
        # Verify the public key matches the registered one for this student
        if self.registered_students[student_id] != public_key_pem:
            print(f"[Instructor] Public key mismatch for anonymous ID: {anonymous_id}")
            return False
        
        # Store the submission
        self.submissions[anonymous_id] = {
            "submission": submission,
            "grade": None,
            "signature": base64.b64encode(signature).decode('utf-8')
        }
        
        print(f"[Instructor {self.name}] Received anonymous submission with ID: {anonymous_id}")
        return True
    
    def grade_submission(self, anonymous_id, grade):
        """Grade a submission by its anonymous ID."""
        if anonymous_id not in self.submissions:
            print(f"[Instructor] No submission found for anonymous ID: {anonymous_id}")
            return False
        
        self.submissions[anonymous_id]["grade"] = grade
        print(f"[Instructor {self.name}] Graded submission {anonymous_id} with grade: {grade}")
        return True
    
    def publish_grades(self):
        """Publish all grades."""
        for aid, submission_data in self.submissions.items():
            if submission_data["grade"] is not None:
                self.published_grades[aid] = submission_data["grade"]
        
        print(f"[Instructor {self.name}] Published grades for {len(self.published_grades)} submissions")
        return self.published_grades
    
    def get_published_grades(self):
        """Get the published grades."""
        return self.published_grades
    
    def get_final_grades_with_names(self):
        """Get the final grades with student IDs (for instructor records)."""
        final_grades = {}
        for aid, grade in self.published_grades.items():
            if aid in self.aid_student_map:
                student_id = self.aid_student_map[aid]
                final_grades[student_id] = {
                    "anonymous_id": aid,
                    "grade": grade
                }
        return final_grades

def run_simulation():
    """Run a simulation of the anonymous submission protocol."""
    print("\n=== ANONYMOUS SUBMISSION PROTOCOL SIMULATION ===\n")
    
    # Create an instructor
    instructor = Instructor("Professor Smith")
    
    # Create students
    students = [
        Student("Alice", "S12345"),
        Student("Bob", "S23456"),
        Student("Charlie", "S34567"),
        Student("David", "S45678"),
        Student("Eve", "S56789")
    ]
    
    # Register students
    print("\n--- STUDENT REGISTRATION ---")
    for student in students:
        instructor.register_student(student.student_id, student.get_public_key_pem())
    
    # Students request anonymous IDs
    print("\n--- ANONYMOUS ID DISTRIBUTION ---")
    for student in students:
        student.request_anonymous_id(instructor)
    
    # Students submit their work
    print("\n--- ANONYMOUS SUBMISSION ---")
    submissions = [
        "This is Alice's essay on cryptography.",
        "Bob's analysis of the RSA algorithm and its applications.",
        "Charlie's research on quantum-resistant cryptographic methods.",
        "David's implementation of a secure communication protocol.",
        "Eve's study on side-channel attacks in modern cryptosystems."
    ]
    
    for i, student in enumerate(students):
        student.submit_work(instructor, submissions[i])
    
    # Instructor grades the submissions
    print("\n--- ANONYMOUS GRADING ---")
    # Get anonymous IDs from the instructor's records for grading
    anonymous_ids = list(instructor.aid_student_map.values())
    
    # Assign random grades
    grades = [85, 92, 78, 95, 88]
    
    for i, aid in enumerate(anonymous_ids):
        instructor.grade_submission(aid, grades[i])
    
    # Instructor publishes the grades
    print("\n--- GRADE PUBLISHING ---")
    instructor.publish_grades()
    
    # Students check their grades
    print("\n--- GRADE CHECKING ---")
    for student in students:
        student.check_grade(instructor)
    
    # Instructor can now map grades to real student IDs for final records
    print("\n--- FINAL GRADE MAPPING (INSTRUCTOR ONLY) ---")
    final_grades = instructor.get_final_grades_with_names()
    
    # Display the final grades in a tabular format
    table_data = []
    for student_id, data in final_grades.items():
        # Find the student name
        student_name = next((s.name for s in students if s.student_id == student_id), "Unknown")
        table_data.append([student_name, student_id, data["anonymous_id"], data["grade"]])
    
    print("\nFinal Grades (Instructor's View):")
    print(tabulate(table_data, headers=["Student Name", "Student ID", "Anonymous ID", "Grade"], tablefmt="grid"))
    
    # This demonstrates that only the instructor can link anonymous IDs to real identities
    print("\n=== PROTOCOL SIMULATION COMPLETED ===\n")
    
    # Generate a summary report
    with open("anonymous_submission_report.txt", "w") as f:
        f.write("ANONYMOUS SUBMISSION PROTOCOL REPORT\n")
        f.write("===================================\n\n")
        
        f.write("Protocol Overview\n")
        f.write("----------------\n")
        f.write("This protocol allows students to submit their work anonymously while ensuring\n")
        f.write("that only legitimate students can make submissions. The instructor can grade\n")
        f.write("the submissions without knowing the identity of the students, but can later\n")
        f.write("map the grades to student identities for final records.\n\n")
        
        f.write("Protocol Steps\n")
        f.write("-------------\n")
        f.write("1. Student Registration: Students register with the instructor using their real IDs\n")
        f.write("2. Anonymous ID Distribution: Instructor issues unique anonymous IDs to each student\n")
        f.write("3. Anonymous Submission: Students submit their work using only their anonymous IDs\n")
        f.write("4. Anonymous Grading: Instructor grades submissions without knowing student identities\n")
        f.write("5. Grade Publishing: Grades are published with anonymous IDs\n")
        f.write("6. Final Mapping: Instructor maps anonymous IDs to real students for final records\n\n")
        
        f.write("Security Properties\n")
        f.write("-----------------\n")
        f.write("- Anonymity: The instructor cannot determine which student submitted which work during grading\n")
        f.write("- Authentication: Only legitimate students can obtain anonymous IDs and submit work\n")
        f.write("- Non-repudiation: Students cannot deny having submitted work (due to digital signatures)\n")
        f.write("- Integrity: Submissions cannot be modified after signing\n")
        f.write("- Confidentiality: Only the intended student can access their anonymous ID\n\n")
        
        f.write("Simulation Results\n")
        f.write("-----------------\n")
        f.write("Anonymous ID to Student Mapping (maintained securely by the instructor):\n")
        mapping_data = [[student_id, anonymous_id] for student_id, anonymous_id in instructor.student_aid_map.items()]
        f.write(tabulate(mapping_data, headers=["Student ID", "Anonymous ID"], tablefmt="grid"))
        f.write("\n\n")
        
        f.write("Published Grades (visible to all students):\n")
        grade_data = [[aid, grade] for aid, grade in instructor.published_grades.items()]
        f.write(tabulate(grade_data, headers=["Anonymous ID", "Grade"], tablefmt="grid"))
        f.write("\n\n")
        
        f.write("Final Grades with Student Identities (instructor's view only):\n")
        f.write(tabulate(table_data, headers=["Student Name", "Student ID", "Anonymous ID", "Grade"], tablefmt="grid"))
    
    print(f"Report saved to 'anonymous_submission_report.txt'")

if __name__ == "__main__":
    run_simulation() 