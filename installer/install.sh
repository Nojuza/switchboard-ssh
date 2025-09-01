#!/usr/bin/env bash
# Installer script for switchboard-ssh
# Copies the application into a shared directory and creates a
# command line entry point so it can be run as `switchboard`.

set -euo pipefail

# Determine repository root so the script works from any location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SOURCE_FILE="$PROJECT_ROOT/switchboard.py"
REQUIREMENTS_FILE="$PROJECT_ROOT/requirements.txt"

# Determine installation prefix. Allow overriding with PREFIX env var.
OS_NAME=$(uname -s)
if [[ "$OS_NAME" == "Darwin" ]]; then
    DEFAULT_PREFIX="/usr/local"
else
    DEFAULT_PREFIX="/usr"
fi
PREFIX="${PREFIX:-$DEFAULT_PREFIX}"

SHARE_DIR="$PREFIX/share/switchboard-ssh"
BIN_DIR="$PREFIX/bin"

VENV_DIR="$SHARE_DIR/venv"

# Create directories
install -d "$SHARE_DIR" "$BIN_DIR"

# Set up virtual environment and install dependencies
if command -v python3 >/dev/null 2>&1; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    if [[ -f "$REQUIREMENTS_FILE" ]]; then
        echo "Installing Python dependencies..."
        "$VENV_DIR/bin/pip" install -r "$REQUIREMENTS_FILE"
    fi
else
    echo "python3 is required to install dependencies" >&2
    exit 1
fi

# Copy main script
install -m 644 "$SOURCE_FILE" "$SHARE_DIR/switchboard.py"

# Create wrapper executable
cat > "$BIN_DIR/switchboard" <<WRAPPER
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python" "$SHARE_DIR/switchboard.py" "\$@"
WRAPPER
chmod 755 "$BIN_DIR/switchboard"

echo "switchboard installed to $BIN_DIR/switchboard"
