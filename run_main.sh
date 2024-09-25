#!/bin/bash

# Set absolute paths
SCRIPT_DIR="<directory/run_main.sh>"
MAIN_PY="$SCRIPT_DIR/main.py"

# Check if python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 could not be found. Please install Python 3."
    exit 1
fi

# Check if main.py exists
if [ ! -f "$MAIN_PY" ]; then
    echo "ERROR: $MAIN_PY does not exist."
    exit 1
fi

# Check if main.py is already running
if pgrep -f "$MAIN_PY" > /dev/null; then
    echo "ERROR: $MAIN_PY is already running."
    exit 1
fi

# Set execute permissions for the script
chmod +x "$MAIN_PY"

# Run the main.py script
if python3 "$MAIN_PY"; then
    echo "main.py completed successfully."
else
    echo "ERROR: main.py failed with exit code $?"
    exit 1
fi
