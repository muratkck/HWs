"""
CENG418 Assignment - 2 | Q2
    Damla Keleş     280201057
    Murat Küçük     280201052
    Yusuf Atmaca    270201084
"""

"""REQUIREMENT 1: Define Core Classes"""
class Subject:
    """Subject: Has a _unique identifier_ and a _capability list_."""
    
    def __init__(self, id):
        self.id = id
        self.capabilities = []
    
    def __str__(self):
        return f"Subject({self.id})"
    
    def __repr__(self):
        return self.__str__()

class Object:
    """Object: Has a _unique identifier_ and a _list of owners_."""
    
    def __init__(self, id):
        self.id = id
        self.owners = []

    def __str__(self):
        return f"Object({self.id})"

    def __repr__(self):
        return self.__str__()

class Capability:
    """Capability: Encapsulates a reference to an object and a list of rights
        (e.g., ['read', 'write','own'])."""
        
    def __init__(self, obj, rights=None):
        self.object = obj
        self.rights = rights or []  # List of rights ('read', 'write', 'own', etc.)

    def __str__(self):
        return f"Capability({self.object.id}, {self.rights})"

    def __repr__(self):
        return self.__str__()


"""    REQUIREMENT 2: Capability System Behavior
    REQUIREMENT 3: Implement the Helper Functions"""
def add_capability(requester, subject, obj, rights):
    """
    Add rights to a subject for an object.
    Only a subject with _own_ right can modify capabilities.

    Args:
        requester: The subject requesting to add rights
        subject: The subject to receive the rights
        obj: The object to add rights for
        rights: List of rights to add
    """
    # Check if requester has the _own_ right
    if requester not in obj.owners:
        raise PermissionError(f"{requester} does not have 'own' right on {obj}")

    # Find or create capability for this subject and object
    capability = None
    for cap in subject.capabilities:
        if cap.object == obj:
            capability = cap
            break
    
    if capability is None:
        capability = Capability(obj, [])
        subject.capabilities.append(capability)

    # Add each right that isn't already in the capability
    for right in rights:
        if right not in capability.rights:
            capability.rights.append(right)

            # If _own_ right is granted, add subject to object's owner list
            if right == 'own' and subject not in obj.owners:
                obj.owners.append(subject)
    
    return True

def remove_capability(requester, subject, obj, rights=None):
    """
    Remove rights from a subject for an object.
    If rights is None, removes all capabilities for the object.
    Only a subject with 'own' right can modify capabilities.
    
    Args:
        requester: The subject requesting to remove rights
        subject: The subject to remove rights from
        obj: The object to remove rights for
        rights: List of rights to remove (None for all)
    """
    # Check if requester has the 'own' right
    if requester not in obj.owners:
        raise PermissionError(f"{requester} does not have 'own' right on {obj}")
    
    # Find capability for this subject and object
    capability = None
    cap_index = -1
    for i, cap in enumerate(subject.capabilities):
        if cap.object == obj:
            capability = cap
            cap_index = i
            break
    
    if capability is None:
        # No capability to remove
        return True
    
    if rights is None:
        # Remove all rights (entire capability)
        subject.capabilities.pop(cap_index)
        
        # If subject had _own_ right, remove from object's owner list
        if 'own' in capability.rights and subject in obj.owners:
            obj.owners.remove(subject)
    else:
        # Remove specific rights
        for right in rights:
            if right in capability.rights:
                capability.rights.remove(right)
                
                # If _own_ right is removed, remove from object's owner list
                if right == 'own' and subject in obj.owners:
                    obj.owners.remove(subject)
        
        # If no rights left, remove the capability
        if not capability.rights:
            subject.capabilities.pop(cap_index)
    
    return True

def check_access(subject, obj, right):
    """
    Check if a subject has a specific right on an object.
    
    Args:
        subject: The subject to check
        obj: The object to check against
        right: The specific right to check for
        
    Returns:
        True if subject has the right, False otherwise
    """
    # Find capability for this subject and object
    for cap in subject.capabilities:
        if cap.object == obj and right in cap.rights:
            return True
    
    return False

def get_owners(obj):
    """
    Returns list of subjects who have the own right.
    
    Args:
        obj: The object to get owners for
        
    Returns:
        List of subjects who are owners
    """
    return obj.owners.copy()
