from pathlib import Path

# ============================================================
# THREAT-TRACE PROJECT STRUCTURE CREATOR
# SIH 2026 - Problem Statement 26106
# ============================================================

# Main project folder
project = Path("threat-trace")

# Backend folder
backend = project / "backend"

# Create folders
backend.mkdir(parents=True, exist_ok=True)

# Files that we will create
files = {
    backend / "main.py": "",
    backend / "parser.py": "",
    backend / "ip_extractor.py": "",
    backend / "geolocation.py": "",
    backend / "ai_analyzer.py": "",
    backend / "schemas.py": "",
    backend / "requirements.txt": "",
    backend / ".env": "",
}

# Create every file
for file_path, content in files.items():
    file_path.write_text(content, encoding="utf-8")

# Create README
readme = project / "README.md"

readme.write_text(
    """# Threat-Trace

SIH 2026 - Problem Statement 26106

Automated Email Forensics, Origin Traceability &
Threat Intelligence Platform.

## Backend Structure

- main.py
- parser.py
- ip_extractor.py
- geolocation.py
- ai_analyzer.py
- schemas.py
- requirements.txt
- .env
""",
    encoding="utf-8"
)

print()
print("=" * 60)
print("       THREAT-TRACE PROJECT CREATED SUCCESSFULLY")
print("=" * 60)
print()

print("threat-trace/")
print("│")
print("├── backend/")
print("│   ├── main.py")
print("│   ├── parser.py")
print("│   ├── ip_extractor.py")
print("│   ├── geolocation.py")
print("│   ├── ai_analyzer.py")
print("│   ├── schemas.py")
print("│   ├── requirements.txt")
print("│   └── .env")
print("│")
print("└── README.md")

print()
print("All folders and files have been created.")
print("Now open the 'threat-trace' folder in VS Code.")