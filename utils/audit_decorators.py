from functools import wraps
from flask import request, session, current_app
from flask_login import current_user
from utils.audit_logger import audit_logger, AuditEventType, AuditSeverity
import traceback

def audit_action(event_type: AuditEventType, 
                severity: AuditSeverity = AuditSeverity.LOW,
                resource: str = None,
                action: str = None):
    """Decorator to automatically audit Flask route actions."""
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get user information
            user_id = str(current_user.id) if current_user.is_authenticated else None
            username = current_user.username if current_user.is_authenticated else None
            
            # Get request information
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            user_agent = request.headers.get('User-Agent', '')
            session_id = session.get('_id', '')
            
            # Determine resource and action
            route_resource = resource or request.endpoint
            route_action = action or f"{request.method} {request.path}"
            
            # Prepare details
            details = {
                'method': request.method,
                'path': request.path,
                'args': dict(request.args),
                'endpoint': request.endpoint
            }
            
            # Add form data for POST requests (excluding sensitive data)
            if request.method == 'POST' and request.form:
                form_data = dict(request.form)
                # Remove sensitive fields
                sensitive_fields = ['password', 'token', 'secret', 'key']
                for field in sensitive_fields:
                    if field in form_data:
                        form_data[field] = '[REDACTED]'
                details['form_data'] = form_data
            
            success = True
            error_message = None
            
            try:
                # Execute the original function
                result = f(*args, **kwargs)
                return result
            
            except Exception as e:
                success = False
                error_message = str(e)
                
                # Log the error with higher severity
                audit_logger.log_event(
                    event_type=AuditEventType.ERROR,
                    severity=AuditSeverity.HIGH,
                    user_id=user_id,
                    username=username,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    resource=route_resource,
                    action=route_action,
                    details={**details, 'traceback': traceback.format_exc()},
                    success=False,
                    error_message=error_message,
                    session_id=session_id
                )
                
                # Re-raise the exception
                raise
            
            finally:
                # Log the audit event
                audit_logger.log_event(
                    event_type=event_type,
                    severity=severity,
                    user_id=user_id,
                    username=username,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    resource=route_resource,
                    action=route_action,
                    details=details,
                    success=success,
                    error_message=error_message,
                    session_id=session_id
                )
        
        return decorated_function
    return decorator

def audit_login_attempt(success: bool, username: str = None, error_message: str = None):
    """Log login attempts."""
    
    ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '')
    
    event_type = AuditEventType.LOGIN if success else AuditEventType.LOGIN_FAILED
    severity = AuditSeverity.LOW if success else AuditSeverity.MEDIUM
    
    details = {
        'method': request.method,
        'path': request.path,
        'attempted_username': username
    }
    
    audit_logger.log_event(
        event_type=event_type,
        severity=severity,
        username=username if success else None,
        ip_address=ip_address,
        user_agent=user_agent,
        resource='authentication',
        action='login_attempt',
        details=details,
        success=success,
        error_message=error_message
    )

def audit_logout(username: str):
    """Log logout events."""
    
    ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '')
    session_id = session.get('_id', '')
    
    audit_logger.log_event(
        event_type=AuditEventType.LOGOUT,
        severity=AuditSeverity.LOW,
        username=username,
        ip_address=ip_address,
        user_agent=user_agent,
        resource='authentication',
        action='logout',
        details={
            'method': request.method,
            'path': request.path
        },
        success=True,
        session_id=session_id
    )

def audit_process_kill(pid: int, process_name: str, success: bool, error_message: str = None):
    """Log process termination attempts."""
    
    user_id = str(current_user.id) if current_user.is_authenticated else None
    username = current_user.username if current_user.is_authenticated else None
    ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '')
    session_id = session.get('_id', '')
    
    severity = AuditSeverity.HIGH if success else AuditSeverity.CRITICAL
    
    details = {
        'pid': pid,
        'process_name': process_name,
        'method': request.method,
        'path': request.path
    }
    
    audit_logger.log_event(
        event_type=AuditEventType.PROCESS_KILL,
        severity=severity,
        user_id=user_id,
        username=username,
        ip_address=ip_address,
        user_agent=user_agent,
        resource='process_management',
        action=f'kill_process_{pid}',
        details=details,
        success=success,
        error_message=error_message,
        session_id=session_id
    )
