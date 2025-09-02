# switchboard-ssh

A user-friendly terminal SSH client.

## About

`switchboard-ssh` provides an interactive interface for managing and connecting
to multiple SSH profiles from the command line. It lets you store connection
details, search through profiles and launch SSH sessions without typing long
commands.

## Installation

The project requires **Python 3.8+** and `pip`. The installer script will copy
the application into a shared directory and create a dedicated virtual
environment for its Python dependencies. Make sure the installer is run as root
or has permissions to create/modify files in the /usr directory. 

```bash
git clone https://github.com/nojuza/switchboard-ssh.git
cd switchboard-ssh
sudo ./installer/install.sh
```

This installs the `switchboard` command to your `$PREFIX/bin` (default
`/usr/local/bin`) and sets up an isolated virtual environment in
`$PREFIX/share/switchboard/venv` with dependencies listed in
`requirements.txt` (`prompt_toolkit`, `pexpect`, `cryptography`, etc.). To set
a different installation prefix, provide `PREFIX=/path` before running the
script.


If you prefer manual installation you can install the dependencies directly:

```bash
pip install -r requirements.txt
```

and run the application with:

```bash
python switchboard.py
```

## Usage

Once installed, launch the client with:

```bash
switchboard
```

Profiles are stored in `~/.config/sshpad/connections.json` by default. Use
`--config /path/to/file.json` to specify a different location. The interface
offers convenient key bindings such as arrow keys for navigation, `a` to add a
profile, `e` to edit, `d` to delete, `/` to search, and `s` to save.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.
Please add docstrings for new code.
