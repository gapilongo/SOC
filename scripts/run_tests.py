"""
Test runner script for LG-SOTF.

This script runs the test suite with proper configuration
and generates coverage reports.
"""

import os
import subprocess
import sys
from pathlib import Path


def run_tests():
    """Run the test suite."""
    print("🧪 Running LG-SOTF test suite...")
    
    # Change to project root
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    # Run pytest with coverage
    cmd = [
        "python", "-m", "pytest",
        "tests/",
        "-v",
        "--cov=lg_sotf",
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov",
        "--cov-report=xml:coverage.xml",
        "--cov-fail-under=80",
        "--strict-markers",
        "--tb=short"
    ]
    
    try:
        result = subprocess.run(cmd, check=True)
        print("\n✅ All tests passed!")
        print("📊 Coverage report generated:")
        print("   - HTML: htmlcov/index.html")
        print("   - XML: coverage.xml")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Tests failed with exit code {e.returncode}")
        return False
    except Exception as e:
        print(f"\n❌ Unexpected error running tests: {e}")
        return False


def main():
    """Main function."""
    success = run_tests()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()