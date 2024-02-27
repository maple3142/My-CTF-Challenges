#!/usr/bin/python

#Referense: https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/hitcon-ctf-2021/Vulpixelize/run.py

import os, sys
import uuid
from random import shuffle
from subprocess import run, PIPE
from flask import Flask, request, make_response
import time
import requests
import re
import logging
from flagstego import GenL33tFlag
import json
import atexit

app  = Flask(__name__)

RateLimit = 300
CTFdHost = "qual.eof.ais3.org"
ChallengeHost = "10.105.0.21"
InstancerPort = 24000
ChallengeName = "Internal(Web)"
ContainerPrefix = "internal_"
PortPool = list(range(11001,12000)) # don't confict with other challenge in the same host
OriginalFlag = "just_some_funny_nginx_feature"
FlagFormat = "AIS3{%s}"
FlagDirectory = "flag"
LogFile = "all.log"
Network_Prefix = "10.200." # don't confict with other challenge in the same host
SubnetPool = []
RunningInstance = {}
instance_describe = lambda instance: f"<code>http://{ChallengeHost}:{instance['port']}</code>"
if Network_Prefix[-1]!=".":
    Network_Prefix += "."
if os.path.isfile(".runninginstance"):
    with open(".runninginstance") as f:
        RunningInstance_ = json.loads(f.read())
    os.unlink(".runninginstance")
    for teamid_str in RunningInstance_:
        RunningInstance[int(teamid_str)] = RunningInstance_[teamid_str]
os.makedirs(FlagDirectory, exist_ok=True)
flag_generator = GenL33tFlag(b"s3cr3t_k3y", OriginalFlag)
print(flag_generator.regex(True))

def save_running_instance():
    with open(".runninginstance", "w") as f:
        f.write(json.dumps(RunningInstance))
atexit.register(save_running_instance)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s: [%(levelname)s] %(message)s')
stdout_handler = logging.StreamHandler()
stdout_handler.setLevel(logging.INFO)
stdout_handler.setFormatter(formatter)
file_handler = logging.FileHandler(LogFile)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(stdout_handler)


INDEXHTML = f'''
<h1>Instancer of {ChallengeName}</h1>
<form action="/" method="POST">
<input type="text" name="token" placeholder="CTFd access token" />
<input type="checkbox" name="recreate" id="recreate_checkbox" />
<label for="recreate_checkbox">Recreate a instance.</label><br><br>
<button type="submit">Create Instance</button>
</form>
<p>You can get your token from <a href="http://{CTFdHost}/settings#tokens">here</a>.</p>
<p>Instance will shutdown in {RateLimit} seconds.</p>
'''

def genprefix():
    prefix = []
    for i in range(2**13):
        prefix.append("%s%d.%d/29"%(Network_Prefix,i>>5,(i<<3)&0xff))
    return prefix

def getteamid(token):
    try:
        if re.fullmatch("^ctfd_[0-9a-f]{64}$",token) is None:
            logging.info(f"Token's format is invalid: {token}")
            return None
        ctfdurl = "http://%s/api/v1/users/me"%CTFdHost
        res = requests.get(ctfdurl, headers={"Authorization": "Token %s"%token, "Content-Type": "application/json"})
        if res.status_code != 200:
            logging.info(f"Couldn't login as token: {token}, status_code: {res.status_code}, res: {res.text}")
            return None
        resobj = res.json()
        if not resobj["success"]:
            logging.info(f"Couldn't login as token: {token}, status_code: {res.status_code}, res: {res.text}")
            return None
    except Exception as e:
        logging.info(f"Exception while verify token: {token}, {e}")
        return None
    return resobj["data"]["id"]

def genteamflag(teamid):
    flag = FlagFormat%(flag_generator.stego(int(teamid)))
    flag_path = os.path.join(FlagDirectory, f"flag_{teamid}")
    with open(os.path.join(FlagDirectory, f"flag_{teamid}"), "w") as f:
        f.write(flag)
    return flag_path

def my_exec(cmds):
    return run(cmds, stdout=PIPE, stderr=PIPE)

def write_log(instanceid, errormsg):
    with open(LogFile, "a") as f:
        f.write("%s: %s"%(instanceid, errormsg))

def create_instance(teamid):
    name = ContainerPrefix+"%s_%s"%(teamid,uuid.uuid4().hex[:16])
    if len(PortPool)==0:
        logger.critical(f"[{name}] PortPool is empty")
        return {"error": name}
    if len(SubnetPool)==0:
        logger.critical(f"[{name}] SubnetPool is empty")
        return {"error": name}
    try:
        flag_path = genteamflag(teamid)
    except Exception as e:
        logging.warning(f"[{name}] Couldn't generate the flag: {e}")
        return {"error": name}
    port = PortPool.pop()
    subnet = SubnetPool.pop()
    p = my_exec(["sudo", f"PORT={port}", f"SUBNET={subnet}", f"FLAGFILE={flag_path}", "docker-compose", "-p", name, "up", "-d"])
    if p.stdout:
        result = p.stdout.decode()
        logger.debug(f"[{name}] "+result)
    if p.stderr:
        result = p.stderr.decode()
        logger.info(f"[{name}] "+result)
    if p.returncode != 0:
        logger.warning(f"[{name}] Failed when create instance.")
        return {"error": name}
    logger.info(f"[{name}] instance created.")
    return {"expire": time.time()+RateLimit, "port": port, "subnet": subnet, "id": name}

def create_instance_(teamid):
    port = PortPool.pop()
    subnet = SubnetPool.pop()
    name = "%s"%uuid.uuid4().hex[:16]
    #my_exec(["docker", "network", "prune", "-f", "--filter", "label=NPO"])
    #p = my_exec(["./create_instance.sh", name, str(port), subnet, str(RateLimit), "team%s"%teamid, name])
    p = my_exec(["sudo", f"PORT={port}", f"SUBNET={subnet}", "docker-compose", "-p", name, ])
    #print(p.returncode)
    result = p.stdout.decode()
    if p.stderr:
        result = p.stderr.decode()
    print(result)
    with open(LogFile, "a") as f:
        f.write("%s: %s"%(name, result))
    if p.returncode != 0:
        return {"error": name}
    return {"expire": time.time()+RateLimit, "url": "http://team%s:%s@%s:%d/"%(teamid, name, ChallengeHost, port), "port": port, "subnet": subnet, "id": name}

def free_resource(teamid):
    if not teamid in RunningInstance:
        return
    #name = ContainerPrefix+"%s_%s"%(teamid,uuid.uuid4().hex[:16])
    name = RunningInstance[teamid]["id"]
    p = my_exec(["sudo", f"PORT=12345", f"SUBNET=10.0.0.0/30", f"FLAGFILE=./flag", "docker-compose", "-p", name, "down"])
    if p.stdout:
        result = p.stdout.decode()
        logger.debug(f"[{name}] docker-compose down: "+result)
    if p.stderr:
        result = p.stderr.decode()
        logger.info(f"[{name}] docker-compose down: "+result)
    PortPool.append(RunningInstance[teamid]["port"])
    SubnetPool.append(RunningInstance[teamid]["subnet"])
    shuffle(PortPool)
    shuffle(SubnetPool)
    RunningInstance.pop(teamid)

def free_expire():
    teamid_to_free = []
    for teamid in RunningInstance:
        if (time.time() >= RunningInstance[teamid]["expire"]):
            #free_resource(teamid)
            teamid_to_free.append(teamid)
    for teamid in teamid_to_free:
        free_resource(teamid)

@app.route('/')
def index():
    return INDEXHTML

@app.route('/', methods=['POST'])
def submit():
    token = request.form["token"]
    teamid = getteamid(token)
    if teamid is None:
        return "Invalid Token.", 500

    msg = ""
    
    if (teamid in RunningInstance) and (time.time() < RunningInstance[teamid]["expire"]) and not ("recreate" in request.form):
        msg += '<p>Your team can create another instance after %d seconds.</p>'%(RunningInstance[teamid]["expire"]-time.time())
        msg += '<p>You might still be able to access the instance at %s.</p>'%(instance_describe(RunningInstance[teamid]))
        msg += '<p>If you want to recreate a instance, please check the "Recreate a instance." checkbox.</p>'
    else:
        free_resource(teamid)
        free_expire()
        team_instance = create_instance(teamid)
        if "error" in team_instance:
            msg += '<p>Something error. Please send the following id to admin!!</p>'
            msg += '<p>ID: %s</p>'%team_instance["error"]
        else:
            RunningInstance[teamid] = team_instance
            msg += '<p>Success! Your can access your instance at %s (Please wait about 10 seconds for service start.)</p>'%(instance_describe(RunningInstance[teamid]))
    
    return msg

if __name__ == '__main__':
    #PortPool = list(range(30000, 40000))
    print(RunningInstance)
    SubnetPool = genprefix()
    shuffle(PortPool)
    shuffle(SubnetPool)
    for teamid in RunningInstance:
        PortPool.remove(RunningInstance[teamid]['port'])
        SubnetPool.remove(RunningInstance[teamid]['subnet'])
    #print(create_instance())
    app.run('0.0.0.0', InstancerPort, debug=False)
