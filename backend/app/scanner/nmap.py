import ipaddress
import subprocess

from defusedxml.ElementTree import fromstring

from app.scanner.types import Service


def parse_xml(xml: str, address: str, ports: list[int]) -> list[Service]:
    root = fromstring(xml)
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValueError("Nmap did not finish successfully")
    hosts = root.findall("host")
    host = next(
        (h for h in hosts if any(a.get("addr") == address for a in h.findall("address"))), None
    )
    if host is None or host.get("timedout") == "true":
        raise ValueError("Target missing or timed out")
    if host.find("status") is None or host.find("status").get("state") != "up":
        raise ValueError("Reachability not established; host down is unconfirmed")
    found = {}
    for node in host.findall("ports/port"):
        port = int(node.get("portid"))
        if port not in ports or node.get("protocol") != "tcp":
            continue
        state = node.find("state")
        svc = node.find("service")

        def attr(name, default="", svc=svc):
            return svc.get(name, default) if svc is not None else default

        found[port] = Service(
            address=address,
            port=port,
            state=state.get("state") if state is not None else "unknown",
            name=attr("name"),
            product=attr("product"),
            version=attr("version"),
            tunnel=attr("tunnel"),
            confidence=int(attr("conf", "0")),
        )
    # Nmap summarizes omitted ports. Expand only a single, unambiguous summary
    # whose count matches every missing requested port. Never assume absence=closed.
    missing = set(ports) - set(found)
    summaries = host.findall("ports/extraports")
    if missing and len(summaries) == 1 and int(summaries[0].get("count", "0")) == len(missing):
        for p in missing:
            found[p] = Service(address=address, port=p, state=summaries[0].get("state", "unknown"))
    if set(found) != set(ports):
        raise ValueError("Incomplete TCP port coverage in Nmap result")
    return sorted(found.values(), key=lambda s: s.port)


def scan_address(address: str, ports: list[int], timeout: int) -> list[Service]:
    ip = ipaddress.ip_address(address)  # Only pinned IPs ever reach subprocess.
    args = [
        "nmap",
        "-sT",
        "-sV",
        "--version-light",
        "-Pn",
        "-n",
        "-T3",
        "--max-rate",
        "30",
        "--max-retries",
        "2",
        "--host-timeout",
        f"{timeout}s",
        "-p",
        ",".join(map(str, ports)),
        "-oX",
        "-",
    ]
    if ip.version == 6:
        args.append("-6")
    args.append(str(ip))
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 10, check=False)
    if proc.returncode:
        raise ValueError(f"Nmap execution failed (exit {proc.returncode})")
    return parse_xml(proc.stdout, address, ports)
