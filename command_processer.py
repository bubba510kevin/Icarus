import shlex
import json
import importlib
import os
import subprocess

def load_functions(module_name="commands"):
    module = importlib.import_module(module_name)
    return {name: func for name, func in vars(module).items() if callable(func)}

def parse_command(command_string):
    parts = shlex.split(command_string)
    if not parts:
        raise ValueError("No command provided")
    return parts[0], parts[1:]

def parse_flags(args, flag_definitions):
    """Parse and separate known flags from positional args"""
    flags = []
    positional = []
    for arg in args:
        if arg in flag_definitions:
            flags.append(arg)
        else:
            positional.append(arg)
    return flags, positional

def main(command_string, commands_json="commands.json"):
    # Load definitions
    with open(commands_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    commands = data["command"]
    flag_definitions = data["flags"]
    func_map = load_functions()

    cmd_name, args = parse_command(command_string)
    flags, positional = parse_flags(args, flag_definitions)

    # --- Determine command type ---
    if cmd_name in commands["custom"]:
        print(f"Running custom command: {cmd_name}")
        func = func_map.get(cmd_name)
        if not func:
            raise ValueError(f"No Python function defined for custom command '{cmd_name}'")
        return func(flags=flags, args=positional)

    elif cmd_name in commands["CMD"]:
        print(f"Running CMD command: {cmd_name}")
        full_cmd = " ".join([cmd_name] + args)
        return subprocess.run(full_cmd, shell=True).returncode

    else:
        raise ValueError(f"Unknown command: {cmd_name}")






