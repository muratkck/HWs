"""
CENG418 Assignment - 2 | Q1
    Damla Keleş     280201057
    Murat Küçük     280201052
    Yusuf Atmaca    270201084
"""

class SecurityLabel:
    def __init__(self, categories=None):
        """Initialize a security label with a set of categories."""
        self.categories = set(categories) if categories else set()
    
    def __str__(self):
        if not self.categories:
            return "{}"
        return "{" + ", ".join(self.categories) + "}"
    
    def __repr__(self):
        return self.__str__()

class Subject:
    def __init__(self, name, label=None):
        """Initialize a subject with a name and security label."""
        self.name = name
        self.label = label if label else SecurityLabel()
    
    def __str__(self):
        return f"Subject({self.name}, {self.label})"
    
    def __repr__(self):
        return self.__str__()

class Object:
    def __init__(self, name, label=None):
        """Initialize an object with a name and security label."""
        self.name = name
        self.label = label if label else SecurityLabel()
    
    def __str__(self):
        return f"Object({self.name}, {self.label})"
    
    def __repr__(self):
        return self.__str__()

def can_access(subject, obj):
    """
    Check if a subject can access an object based on the lattice-based access control rule.
    Access is allowed if the subject's label is a subset of the object's label.
    
    Args:
        subject (Subject): The subject requesting access.
        obj (Object): The object to be accessed.
        
    Returns:
        bool: True if access is allowed, False otherwise.
    """
    return subject.label.categories.issubset(obj.label.categories)

# Bonus: Read/Write distinction
def can_read(subject, obj):
    """
    Check if a subject can read an object.
    Same as can_access: subject's label must be a subset of object's label.
    """
    return can_access(subject, obj)

def can_write(subject, obj):
    """
    Check if a subject can write to an object.
    Write access requires subject's label to be equal to object's label
    (no write-up rule: prevents writing to objects with higher classification).
    """
    return subject.label.categories == obj.label.categories

# Bonus: Generate and display the lattice structure
def generate_lattice(categories):
    """Generate all possible security labels from a set of categories."""
    import itertools
    labels = []
    
    # Generate all possible subsets of the categories
    for r in range(len(categories) + 1):
        for subset in itertools.combinations(categories, r):
            labels.append(SecurityLabel(subset))
    
    return labels

def display_lattice(categories):
    """Display the partial ordering of the lattice structure."""
    labels = generate_lattice(categories)
    
    print("Lattice Structure (Partial Ordering):")
    print("-------------------------------------")
    
    # Sort labels by the number of categories (level in the lattice)
    labels.sort(key=lambda x: len(x.categories))
    
    # Display the hierarchy
    for i, label1 in enumerate(labels):
        for label2 in labels:
            if (label1.categories != label2.categories and 
                label1.categories.issubset(label2.categories) and
                all(not label1.categories.issubset(other.categories) or 
                    not other.categories.issubset(label2.categories) or
                    other.categories == label1.categories or
                    other.categories == label2.categories
                    for other in labels)):
                print(f"{label1} → {label2}")
