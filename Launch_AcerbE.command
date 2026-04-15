#!/bin/bash
# AcerbE™ Launcher — Mac / Linux
# Double-click this file or run it in terminal

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "=================================================="
echo "  AcerbE™ — Military-Grade Digital Fingerprinter"
echo "=================================================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "  ERROR: Python 3 is not installed."
    echo "  Please install it from https://python.org and try again."
    echo ""
    read -p "Press Enter to exit..."
    exit 1
fi

echo "  Checking dependencies..."
python3 -c "import PIL, cryptography, pikepdf" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "  Installing required packages (first run only)..."
    pip3 install Pillow cryptography pikepdf --quiet --break-system-packages 2>/dev/null || \
    pip3 install Pillow cryptography pikepdf --quiet
fi

echo "  Launching AcerbE™..."
echo "  Your browser will open automatically."
echo "  To stop AcerbE™, close this window or press Ctrl+C"
echo ""

python3 server.py
