#!/usr/bin/env python3
"""Quick test script for ZeroCyber v7 parser and taint engine."""
import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zerocyber_v7.core.parser import LanguageParser

def main():
    parser = LanguageParser()
    print("LanguageParser created successfully!")
    print(f"Available parsers: {list(parser.parsers.keys())}")
    
    # Test parsing a file
    test_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'test_target', 'vulnerable_app.py')
    if os.path.exists(test_file):
        result = parser.parse_file(test_file)
        if result:
            print(f"Parsed {result.path}: {result.language}, {len(result.functions)} functions, {result.loc} LOC")
            for f in result.functions[:5]:
                print(f"  - {f.name} (line {f.start_line}-{f.end_line}), params={f.parameters}")
        else:
            print("Failed to parse file")
    else:
        print(f"Test file not found: {test_file}")

if __name__ == "__main__":
    main()
