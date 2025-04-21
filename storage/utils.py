from .models import AuditLog

def log_file_action(user, file, action, request=None):
    """	
    Logs file actions (upload, download, delete) to the database.
    Args:
        user: The user performing the action.
        file: The file being acted upon.
        action: The action performed (upload, download, delete).
        request: The HTTP request object (optional).
    """
    AuditLog.objects.create(
        user=user,
        file=file,
        action=action,
        ip_address=request.META.get('REMOTE_ADDR') if request else None,
        user_agent=request.META.get('HTTP_USER_AGENT', '') if request else None
    )
