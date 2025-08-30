# app/isolation_controller.py
import os, json, datetime, subprocess, shlex

DEFAULT_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "isolation_state.json")

def _now():
    return datetime.datetime.utcnow().isoformat() + "Z"

def _load_state(path):
    if not os.path.exists(path): return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_state(path, state):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def read_isolation_state(path=DEFAULT_STATE_PATH):
    return _load_state(path)

def _sim_isolate(ip, reason, state_path):
    state = _load_state(state_path)
    state[ip] = {"status":"isolated","reason":reason,"ts":_now(),"mode":"sim"}
    _save_state(state_path, state)
    return f"(sim) {ip} marked isolated"

def _sim_release(ip, state_path):
    state = _load_state(state_path)
    state[ip] = {"status":"released","reason":"release","ts":_now(),"mode":"sim"}
    _save_state(state_path, state)
    return f"(sim) {ip} released"

def _win_firewall_isolate(ip, reason, state_path):
    # Requires elevated privileges on Windows host
    cmd = (
        f'New-NetFirewallRule -DisplayName "CN-Quarantine-{ip}-OUT" -Direction Outbound -Action Block -RemoteAddress {ip}; '
        f'New-NetFirewallRule -DisplayName "CN-Quarantine-{ip}-IN"  -Direction Inbound  -Action Block -RemoteAddress {ip}'
    )
    subprocess.run(["powershell","-Command", cmd], shell=True)
    state = _load_state(state_path)
    state[ip] = {"status":"isolated","reason":reason,"ts":_now(),"mode":"firewall_win"}
    _save_state(state_path, state)
    return f"(firewall_win) {ip} isolated via Windows Firewall"

def _win_firewall_release(ip, state_path):
    cmd = (
        f'Get-NetFirewallRule | Where-Object {{ $_.DisplayName -like "CN-Quarantine-{ip}-*" }} | Remove-NetFirewallRule'
    )
    subprocess.run(["powershell","-Command", cmd], shell=True)
    state = _load_state(state_path)
    state[ip] = {"status":"released","reason":"release","ts":_now(),"mode":"firewall_win"}
    _save_state(state_path, state)
    return f"(firewall_win) {ip} released (rules removed)"

def _linux_firewall_isolate(ip, reason, state_path):
    # Requires host iptables privileges
    cmds = [
        f"iptables -I INPUT  -s {shlex.quote(ip)} -j DROP",
        f"iptables -I OUTPUT -d {shlex.quote(ip)} -j DROP",
    ]
    for c in cmds:
        subprocess.run(["/bin/sh","-lc", c], check=False)
    state = _load_state(state_path)
    state[ip] = {"status":"isolated","reason":reason,"ts":_now(),"mode":"firewall_linux"}
    _save_state(state_path, state)
    return f"(firewall_linux) {ip} isolated via iptables"

def _linux_firewall_release(ip, state_path):
    cmds = [
        f"iptables -D INPUT  -s {shlex.quote(ip)} -j DROP",
        f"iptables -D OUTPUT -d {shlex.quote(ip)} -j DROP",
    ]
    for c in cmds:
        subprocess.run(["/bin/sh","-lc", c], check=False)
    state = _load_state(state_path)
    state[ip] = {"status":"released","reason":"release","ts":_now(),"mode":"firewall_linux"}
    _save_state(state_path, state)
    return f"(firewall_linux) {ip} released (rules deleted)"

def _vbox_isolate(ip, reason, state_path):
    # Requires VirtualBox and VM name in env: VBOX_VM_NAME
    vm = os.environ.get("VBOX_VM_NAME","Kali")
    # setlinkstate1 off (adapter 1)
    subprocess.run(["VBoxManage","controlvm", vm, "setlinkstate1", "off"], check=False)
    state = _load_state(state_path)
    state[ip] = {"status":"isolated","reason":reason,"ts":_now(),"mode":"vbox", "vm": vm}
    _save_state(state_path, state)
    return f"(vbox) VM '{vm}' NIC link off — {ip} isolated"

def _vbox_release(ip, state_path):
    vm = os.environ.get("VBOX_VM_NAME","Kali")
    subprocess.run(["VBoxManage","controlvm", vm, "setlinkstate1", "on"], check=False)
    state = _load_state(state_path)
    state[ip] = {"status":"released","reason":"release","ts":_now(),"mode":"vbox","vm":vm}
    _save_state(state_path, state)
    return f"(vbox) VM '{vm}' NIC link on — {ip} released"

def isolate_host(ip, reason="Operator action", state_path=DEFAULT_STATE_PATH):
    mode = os.environ.get("ISOLATION_MODE","sim").lower()
    if mode == "firewall_win":
        return _win_firewall_isolate(ip, reason, state_path)
    if mode == "firewall_linux":
        return _linux_firewall_isolate(ip, reason, state_path)
    if mode == "vbox":
        return _vbox_isolate(ip, reason, state_path)
    return _sim_isolate(ip, reason, state_path)

def release_host(ip, state_path=DEFAULT_STATE_PATH):
    mode = os.environ.get("ISOLATION_MODE","sim").lower()
    if mode == "firewall_win":
        return _win_firewall_release(ip, state_path)
    if mode == "firewall_linux":
        return _linux_firewall_release(ip, state_path)
    if mode == "vbox":
        return _vbox_release(ip, state_path)
    return _sim_release(ip, state_path)
