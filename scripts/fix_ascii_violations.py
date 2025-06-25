#!/usr/bin/env python3
"""
Quick script to fix ASCII violations in futuristic interface files.
Replaces common emojis and Unicode characters with ASCII equivalents.
"""

from pathlib import Path

# Emoji/Unicode to ASCII replacements
REPLACEMENTS = {
    # Status emojis
    '✅': '[OK]',
    '❌': '[ERROR]',
    '⚠️': '[WARNING]',
    '⚠': '[WARNING]',
    'ℹ️': '[INFO]',
    'ℹ': '[INFO]',
    '✓': '[CHECK]',
    '✕': '[X]',
    
    # Action emojis
    '🚀': '[LAUNCH]',
    '🔄': '[REFRESH]',
    '🔍': '[SEARCH]',
    '🔌': '[CONNECT]',
    '📊': '[CHART]',
    '📈': '[GRAPH]',
    '📨': '[MESSAGE]',
    '📋': '[CLIPBOARD]',
    '📄': '[DOCUMENT]',
    '📁': '[FOLDER]',
    '📂': '[OPEN_FOLDER]',
    '📚': '[LIBRARY]',
    '📦': '[PACKAGE]',
    '💡': '[IDEA]',
    '🎯': '[TARGET]',
    '🎨': '[DESIGN]',
    '🎉': '[SUCCESS]',
    '🎼': '[ORCHESTRATOR]',
    
    # Agent/Tech emojis  
    '🤖': '[AGENT]',
    '🧠': '[AI]',
    '🧬': '[BIOMEDICAL]',
    '🧪': '[TEST]',
    '🧹': '[CLEANUP]',
    '🔬': '[ANALYSIS]',
    '🛡️': '[SECURITY]',
    '🛡': '[SECURITY]',
    '🛑': '[STOP]',
    '⚡': '[FAST]',
    '🌟': '[STAR]',
    '🌐': '[WEB]',
    '🌋': '[VOLCANO]',
    '🔥': '[HEATMAP]',
    '🕸️': '[NETWORK]',
    '🕸': '[NETWORK]',
    '🏗️': '[BUILD]',
    '🏗': '[BUILD]',
    '🏥': '[MEDICAL]',
    '📱': '[MOBILE]',
    '👁️': '[VIEW]',
    '👁': '[VIEW]',
    '👋': '[HELLO]',
    '🔗': '[LINK]',
    '🔴': '[RED]',
    '🟢': '[GREEN]',
    '💓': '[HEARTBEAT]',
    '📅': '[CALENDAR]',
    '🗑️': '[DELETE]',
    '🗑': '[DELETE]',
    '🚨': '[ALERT]',
    '📢': '[BROADCAST]',
    '🎁': '[PACKAGE]',
    '💎': '[PREMIUM]',
    '✨': '[SPARKLE]',
    
    # Box drawing characters
    '└': '+',
    '─': '-',
    '•': '*',
}

def fix_file_ascii(file_path):
    """Fix ASCII violations in a single file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Apply replacements
        for unicode_char, ascii_replacement in REPLACEMENTS.items():
            content = content.replace(unicode_char, ascii_replacement)
        
        # Only write if changes were made
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Fixed ASCII violations in: {file_path}")
            return True
        return False
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def main():
    """Fix ASCII violations in futuristic interface files."""
    base_path = Path(__file__).parent.parent
    futuristic_path = base_path / "interfaces" / "futuristic"
    
    # File patterns to process
    patterns = [
        "**/*.py",
        "**/*.js", 
        "**/*.sh",
        "**/*.md"
    ]
    
    fixed_files = 0
    total_files = 0
    
    for pattern in patterns:
        for file_path in futuristic_path.glob(pattern):
            if file_path.is_file():
                total_files += 1
                if fix_file_ascii(file_path):
                    fixed_files += 1
    
    # Also fix the startup scripts in root
    startup_scripts = [
        base_path / "start-futuristic-interface.sh",
        base_path / "start-futuristic.sh",
        base_path / "test_futuristic_interface.py"
    ]
    
    for script_path in startup_scripts:
        if script_path.exists():
            total_files += 1
            if fix_file_ascii(script_path):
                fixed_files += 1
    
    print(f"\nProcessed {total_files} files, fixed {fixed_files} files")

if __name__ == "__main__":
    main()
