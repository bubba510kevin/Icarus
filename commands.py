#15 to gaven
import json
import logging
import os
import ctypes
import sys



command_registry = {}
def command(name=None):
    """Decorator to register a function as a CLI command"""
    def decorator(func):
        cmd_name = name or func.__name__
        command_registry[cmd_name] = func
        return func
    return decorator

@command
def version():
    with open("version.json", "r") as f:
        data = json.load(f)
    return data.get("version")

@command
def verbose():
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger()
    logger.debug("Verbose mode enabled")
    return logger

y = True
n = False

@command
def fun_1(name, stderr_text, stdout_text):
    """
    Take text output from another function (stderr and stdout)
    and save it as JSON under c:\\saves\\json\\.
    """

    output_data = {
        "stdout": stdout_text,
        "stderr": stderr_text,
        "returncode": 0
    }

    # Ensure save folder exists
    save_dir = r"c:\saves\json"
    os.makedirs(save_dir, exist_ok=True)

    # Add .json extension if missing
    if not name.lower().endswith(".json"):
        name += ".json"

    path = os.path.join(save_dir, name)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=4)

