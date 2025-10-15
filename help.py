import json
import shlex



def help(flags):
    if flags == "null":
        with open("data.json", "r") as f:
            data = json.load(f)
        return data
    else:
        parts = shlex.split(flags)
        flags = [p for p in parts if p.startswith('-')]
        variables = {f"var{i+1}": value for i, value in enumerate(flags)}
        if variables["var1"] == "-cf":
            if variables["var2"] == "-cmd":
                return data["CMD"]
            elif variables["var2"] == "-ct":
                return data["custom"]
        else:
            return f"worng flag: {variables['var1']}"

