# Static CWE-ID -> name lookup for display only (presentation concern, no
# DB/query involvement). Covers the CWEs actually observed in this
# project's ingested data (highest-frequency first), plus common ones a
# future collector run is likely to surface. Anything not listed here
# falls back to just showing the bare ID — see describe_cwe().
CWE_NAMES = {
    "CWE-416": "Use After Free",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-362": "Race Condition (Concurrent Execution using Shared Resource with Improper Synchronization)",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-284": "Improper Access Control",
    "CWE-20": "Improper Input Validation",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-22": "Path Traversal",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-787": "Out-of-bounds Write",
    "CWE-77": "Command Injection",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-59": "Improper Link Resolution Before File Access ('Link Following')",
    "CWE-822": "Untrusted Pointer Dereference",
    "CWE-843": "Type Confusion",
    "CWE-191": "Integer Underflow (Wrap or Wraparound)",
    "CWE-415": "Double Free",
    "CWE-120": "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)",
    "CWE-287": "Improper Authentication",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-295": "Improper Certificate Validation",
    "CWE-126": "Buffer Over-read",
    "CWE-74": "Injection",
    "CWE-285": "Improper Authorization",
    "CWE-78": "OS Command Injection",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-94": "Code Injection",
    "CWE-601": "Open Redirect",
    "CWE-407": "Inefficient Algorithmic Complexity",
    "CWE-789": "Memory Allocation with Excessive Size Value",
    "CWE-367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
    "CWE-73": "External Control of File Name or Path",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-863": "Incorrect Authorization",
    "CWE-451": "User Interface Misrepresentation of Critical Information",
    "CWE-116": "Improper Encoding or Escaping of Output",
    "CWE-269": "Improper Privilege Management",
    "CWE-862": "Missing Authorization",
    "CWE-89": "SQL Injection",
    "CWE-354": "Improper Validation of Integrity Check Value",
    "CWE-93": "CRLF Injection",
    "CWE-208": "Observable Timing Discrepancy",
    "CWE-670": "Always-Incorrect Control Flow Implementation",
    "CWE-91": "XML Injection",
    "CWE-427": "Uncontrolled Search Path Element",
    "CWE-193": "Off-by-one Error",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-1329": "Reliance on Component That is Not Updated",
    "CWE-23": "Relative Path Traversal",
    "CWE-835": "Infinite Loop (Loop with Unreachable Exit Condition)",
    "CWE-346": "Origin Validation Error",
    "CWE-150": "Improper Neutralization of Escape, Meta, or Control Sequences",
    "CWE-669": "Incorrect Resource Transfer Between Spheres",
    # Common CWEs not yet seen in ingested data, kept for completeness.
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-611": "XML External Entity (XXE) Reference",
}


def describe_cwe(cwe_id: str | None) -> str:
    """"CWE-120: Buffer Copy without Checking Size of Input" when known,
    the bare ID for anything not in the table, "Not classified" if there
    is no CWE at all."""
    if not cwe_id:
        return "Not classified"
    name = CWE_NAMES.get(cwe_id)
    return f"{cwe_id}: {name}" if name else cwe_id
