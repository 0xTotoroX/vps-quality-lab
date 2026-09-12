"""Fresh-install-only Xray deployment with ownership and recoverable key state."""

import base64
import json
import secrets
import shlex
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .sources import fetch
from .storage import LabError, write_private


def server_document(config):
    key = X25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw,
                                                    serialization.PrivateFormat.Raw,
                                                    serialization.NoEncryption())
    return {"log": {"loglevel": "warning"},
            "inbounds": [{"tag": "vps-lab-reality", "listen": "0.0.0.0", "port": config.proxy_port,
                          "protocol": "vless", "settings": {"decryption": "none", "clients": [
                              {"id": str(uuid.uuid4()), "flow": "xtls-rprx-vision"}]},
                          "streamSettings": {"network": "raw", "security": "reality",
                                             "realitySettings": {"show": False,
                                                 "target": config.reality_target,
                                                 "serverNames": [config.server_name],
                                                 "privateKey": base64.urlsafe_b64encode(key).decode().rstrip("="),
                                                 "shortIds": [secrets.token_hex(8)]}}}],
            "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
                          {"tag": "block", "protocol": "blackhole"}],
            "routing": {"rules": [{"type": "field", "ip": ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10",
                           "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
                           "224.0.0.0/4", "240.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"],
                           "outboundTag": "block"}]}}


def deploy(remote, config, cache, evidence):
    if not config.allow_deploy or config.mode != "deploy":
        raise LabError("Deployment was not enabled", 4)
    if config.server_config != "/usr/local/etc/xray/config.json":
        raise LabError("Fresh deployment uses the official Xray config path", 2)
    installer, source = fetch("xray-install", cache)
    # A per-host marker makes a partially finished install resumable. Existing installations
    # without that marker are deliberately not adopted by the deployment operation.
    inspect = remote.python("""import json,os,pathlib,subprocess
root=pathlib.Path('/var/lib/vps-quality-lab')
assert os.geteuid()==0, 'deployment requires root'
marker=root/'owner.json'
paths=['/usr/local/bin/xray','/usr/local/etc/xray/config.json','/etc/systemd/system/xray.service','/lib/systemd/system/xray.service']
existing=[p for p in paths if pathlib.Path(p).exists()]
print(json.dumps({'managed':marker.exists(),'existing':existing}))
""")
    if inspect.returncode:
        raise LabError("Cannot inspect Xray ownership", 4)
    state = json.loads(inspect.stdout)
    if state["existing"] and not state["managed"]:
        raise LabError("Existing Xray is not owned by this tool; use adopt mode", 4)
    owner = "/var/lib/vps-quality-lab"
    if not state["managed"]:
        # Bind check catches occupied ports without changing any firewall or service.
        check = remote.python(f"import socket\ns=socket.socket();s.bind(('0.0.0.0',{config.proxy_port}));s.close()")
        if check.returncode:
            raise LabError("Requested proxy port is occupied", 4)
        made = remote.run(f"install -d -m 700 {owner}")
        if made.returncode:
            raise LabError("Cannot create deployment ownership directory")
        remote.write(owner + "/owner.json", json.dumps({"tool": "vps-quality-lab", "version": 1,
                     "config": config.server_config, "installer_sha256": source["sha256"]}).encode())
    owner_record = json.loads(remote.read(owner + "/owner.json"))
    if owner_record.get("tool") != "vps-quality-lab" or owner_record.get("config") != config.server_config:
        raise LabError("Deployment ownership record does not match", 4)
    try:
        pending = remote.read(owner + "/pending.json")
    except FileNotFoundError:
        pending = json.dumps(server_document(config), indent=2).encode()
        remote.write(owner + "/pending.json", pending)
    planned = json.loads(pending)["inbounds"][0]
    reality = planned["streamSettings"]["realitySettings"]
    if (planned["port"] != config.proxy_port or reality["serverNames"] != [config.server_name]
            or reality["target"] != config.reality_target):
        raise LabError("Pending deployment differs from requested port or REALITY target", 4)
    try:
        installed = remote.read(config.server_config)
    except FileNotFoundError:
        installed = None
    if installed and json.loads(installed) not in ({}, json.loads(pending)):
        raise LabError("Managed configuration changed since deployment; refusing overwrite", 4)
    if installed and json.loads(installed) == json.loads(pending):
        active = remote.run("systemctl is-active --quiet xray")
        if active.returncode == 0:
            return json.loads(pending)
    binary = remote.run("test -x /usr/local/bin/xray")
    try:
        receipt = json.loads(remote.read(owner + "/install-complete.json"))
    except FileNotFoundError:
        receipt = None
    expected_receipt = {"installer_sha256": source["sha256"], "xray_version": source["xray_version"]}
    if receipt and receipt != expected_receipt:
        raise LabError("Managed installation version differs; an explicit upgrade is required", 4)
    if binary.returncode or not receipt:
        path = owner + "/install-release.sh"
        try:
            remote.write(path, installer.read_bytes())
        except OSError:
            if remote.read(path) != installer.read_bytes():
                raise LabError("Remote installer differs from reviewed source", 4)
        result = remote.run(f"bash {path} install --without-geodata --version {shlex.quote(source['xray_version'])}", timeout=180)
        write_private(evidence / "xray-install.log", result.stdout + result.stderr)
        if result.returncode:
            raise LabError("Official installer failed; deployment state retained for resume")
        if not receipt:
            remote.write(owner + "/install-complete.json", json.dumps(expected_receipt).encode())
    finish = remote.python(f"""import json,os,pathlib,pwd,grp,subprocess
source=pathlib.Path({(owner+'/pending.json')!r}); target=pathlib.Path({config.server_config!r})
data=source.read_bytes()
assert not target.is_symlink()
if target.exists():
 old=target.read_bytes()
 assert json.loads(old) in ({{}},json.loads(data)), 'configuration changed'
 backup=pathlib.Path({(owner+'/pre-config.json')!r})
 if not backup.exists(): backup.write_bytes(old);os.chmod(backup,0o600)
test=subprocess.run(['/usr/local/bin/xray','run','-test','-config',str(source)],capture_output=True)
assert test.returncode==0, 'Xray rejected generated config'
temp=target.with_name('vps-lab-pending.json');temp.write_bytes(data)
os.chmod(temp,0o640);os.chown(temp,0,pwd.getpwnam('nobody').pw_gid)
os.replace(temp,target)
subprocess.run(['systemctl','enable','xray'],check=True,capture_output=True)
subprocess.run(['systemctl','restart','xray'],check=True,capture_output=True)
subprocess.run(['systemctl','is-active','--quiet','xray'],check=True)
print(json.dumps({{'configured':True,'running':True}}))
""", timeout=30)
    if finish.returncode:
        raise LabError("Xray activation failed; pending keys and previous config retained")
    return json.loads(pending)
