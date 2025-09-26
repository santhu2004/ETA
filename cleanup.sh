#!/bin/bash

echo "========================================"
echo "Cleaning up test outputs..."
echo "========================================"

if [ -d "outputs" ]; then
    echo "Removing outputs directory..."
    rm -rf outputs
    echo "Outputs directory removed."
else
    echo "No outputs directory found."
fi

if [ -d "venv" ]; then
    echo "Removing virtual environment..."
    rm -rf venv
    echo "Virtual environment removed."
else
    echo "No virtual environment found."
fi

echo
echo "========================================"
echo "Cleanup Complete!"
echo "========================================"
echo
echo "To reinstall:"
echo "1. Run install.sh"
echo "2. Or manually: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
echo
