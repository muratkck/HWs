# rbac_system.py

class Permission:
    def __init__(self, name: str):
        self.name = name

    def __eq__(self, other):
        return isinstance(other, Permission) and self.name == other.name

    def __hash__(self):
        return hash(self.name)


class Role:
    def __init__(self, name: str, permissions=None, parent=None):
        self.name = name
        self.permissions = set(permissions) if permissions else set()
        self.parent = parent

    def has_permission(self, permission: Permission) -> bool:
        if permission in self.permissions:
            return True
        if self.parent:
            return self.parent.has_permission(permission)
        return False


class User:
    def __init__(self, username: str, roles=None):
        self.username = username
        self.roles = set(roles) if roles else set()


def has_permission(user: User, permission_name: str) -> bool:
    permission = Permission(permission_name)
    return any(role.has_permission(permission) for role in user.roles)
