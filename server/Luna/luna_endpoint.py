from flask import Flask, request, jsonify
import json

app = Flask(__name__)

master_code = ""




def fillin(is_verifide,ip):
    template = {
        ip:{
            "isverifide":is_verifide
        }
    }
    return template

@app.route('/Luna/22840866924/Icarus/control', methods=['POST'])
def verify():
    ip = request.form.get('ip')

    with open("data.json", "r") as f:
        global data
        data = json.load(f)

    if ip in data:
        if "isverifide" is True:
            pass
        else:
            return "403"
    else:
        code = request.form.get('code')

        with open("dat.json", "a")as f:
            if code == master_code:
                dat = fillin(True,ip)
            else:
                dat = fillin(False,ip)

            json.dump(dat, f, indent=4)
    

        

