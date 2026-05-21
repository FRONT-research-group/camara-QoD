"""
QoD KPI Runner — wired to FRONT-research-group/camara-QoD
Measures:
  - KPI_Enab_QoD_QoSSessionRetainability     (TC_QoD_1)
  - KPI_Enab_QoD_QoSProfileEstablishmentTime (TC_QoD_2)
  - KPI_Enab_QoD_SuccessRate                 (TC_QoD_2)

With iperf3 measurements on a Raspberry Pi UE and API calls to the QoD service.

Only throughput (DL + UL) is used to evaluate QoS conditions.
"""

import csv
import json
import os
import statistics
import subprocess
import threading
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import paramiko
import requests


# ─────────────────────────────────────────────────────────────
# CONFIGURATION — edit these values to match your environment
# ─────────────────────────────────────────────────────────────

# QoD API
QOD_HOST     = "http://10.220.2.50:8584"  # change to your QoD host/IP
QOD_SESSIONS = f"{QOD_HOST}/quality-on-demand/v1/sessions"

# Raspberry Pi (UE)
RPI_HOST    = "10.220.2.128"            # RPi IP address
RPI_USER    = "pi"                       # SSH username
RPI_SSH_KEY = os.path.expanduser("~/.ssh/front_ecdsa")  # SSH private key path
RPI_LOCAL   = True                       # Set True when running this script directly on the RPi

# iPerf3 server (must be reachable from RPi through the 5G network)
IPERF_SERVER = "10.220.2.166"

# Optional SSH access to the iPerf3 server so the script can auto-start
# the background traffic server instance on port 5202.
# Set IPERF_SERVER_SSH_USER = None to skip auto-start (you must start it manually).
IPERF_SERVER_SSH_USER = None          # e.g. "ubuntu" or "pi"
IPERF_SERVER_SSH_KEY  = os.path.expanduser("~/.ssh/front_ecdsa")

# UE identity (RPi IP as seen by the 5G network)
UE_PUBLIC_IP  = "10.45.0.85"
UE_PRIVATE_IP = "10.45.0.85"

# Application server CIDR sent to the QoD API.
# Use 0.0.0.0/0 (any) so the NEF flow descriptor matches all traffic
# from the UE — including iperf3 streams to the measurement server.
# Narrowing to a specific /32 can cause the PCF to reject the bearer
# if the NEF flow matching is strict.
APP_SERVER_CIDR = "0.0.0.0/0"

# QoS profile to test: QOS_E | QOS_S | QOS_M | QOS_L
QOS_PROFILE = "QOS_M"

# ── Thresholds: only DL and UL throughput ────────────────────
# Values match the profile definitions in the camara-QoD README.
# QoS in this deployment acts as a Maximum Bit Rate (MBR) cap.
# A sample is considered QoS-retained when throughput is > 0
# (bearer alive) AND <= the profile cap (cap is being enforced).
QOS_THRESHOLDS = {
    "QOS_E": {"max_dl_mbps": 3,  "max_ul_mbps": 3},
    "QOS_S": {"max_dl_mbps": 10, "max_ul_mbps": 10},
    "QOS_M": {"max_dl_mbps": 20, "max_ul_mbps": 20},
    "QOS_L": {"max_dl_mbps": 40, "max_ul_mbps": 40},
}

# ── iPerf3 ports ─────────────────────────────────────────────
# Measurement probes use the default port (5201).
# Background traffic streams use a separate port to avoid blocking
# the measurement probes (iperf3 server handles one client at a time).
# Start a second iperf3 server instance on the server host:
#   iperf3 -s -p 5202 -D
IPERF_BG_PORT = 5202

# ── TC_QoD_1 settings ────────────────────────────────────────
TC1_DURATION_SEC     = 120  # measurement window per scenario (seconds)
TC1_IPERF_DURATION   = 5     # seconds per iperf3 sample (DL and UL each) — 5s gives ~7 samples/window
TC1_SAMPLE_INTERVAL  = 2    # seconds to wait between consecutive samples
TC1_IPERF_BITRATE    = "8M"  # bitrate per background traffic stream — 2×8M=16M exceeds 10M cap without saturating UL
TC1_NUM_BG_STREAMS   = 2    # parallel background streams launched at start of measurement

# ── TC_QoD_2 settings ────────────────────────────────────────
TC2_NUM_REQUESTS        = 60     # sequential main UE requests per step
TC2_SEQUENTIAL_DELAY    = 1.0    # seconds between sequential requests
TC2_CONCURRENT_STEP_HZ  = 10.0   # concurrent load increment per step (spec: +10 Hz)
TC2_MAX_CONCURRENT_HZ   = 30.0   # stop stepping even if KPIs still pass (safety cap)
TC2_WORKERS_PER_10HZ    = 5      # stress worker threads per 10 Hz block

# ── Output ────────────────────────────────────────────────────
REPORT_PATH     = "results/kpi_report.json"
CSV_REPORT_PATH = "results/kpi_report.csv"

# ── KPI pass/fail thresholds (from ENVELOPE spec) ────────────
RETAINABILITY_THRESHOLD_PCT      = 95.0
SUCCESS_RATE_THRESHOLD_PCT       = 99.9
ESTABLISHMENT_TIME_THRESHOLD_MS  = 1000.0


# ─────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────

@dataclass
class Sample:
    timestamp: float
    dl_mbps: float
    ul_mbps: float
    qos_ok: bool


@dataclass
class ApiResult:
    request_index: int
    success: bool
    status_code: int
    establishment_time_ms: float
    session_id: Optional[str]
    qos_status: Optional[str]
    error: Optional[str]


@dataclass
class RetainabilityResult:
    scenario: str
    qos_profile: str
    total_samples: int
    qos_ok_samples: int
    retainability_pct: float
    avg_dl_mbps: float
    min_dl_mbps: float
    max_dl_mbps: float
    p95_dl_mbps: float
    stdev_dl_mbps: float
    avg_ul_mbps: float
    min_ul_mbps: float
    max_ul_mbps: float
    p95_ul_mbps: float
    stdev_ul_mbps: float
    threshold_met: bool          # retainability >= 95% (S3 only)
    scenario_check_ok: bool = False   # scenario-specific validation
    scenario_check_desc: str = ""     # human-readable description of what was checked
    samples: List[dict] = field(default_factory=list)


@dataclass
class ApiKpiResult:
    scenario: str
    concurrent_hz: float         # concurrent background load applied during this step
    total_requests: int
    successful: int
    failed: int
    success_rate_pct: float
    avg_establishment_ms: float
    p95_establishment_ms: float
    max_establishment_ms: float
    min_establishment_ms: float
    p50_establishment_ms: float
    stdev_establishment_ms: float
    success_rate_ok: bool        # success rate >= 99.9%
    establishment_time_ok: bool  # max establishment time < 1000 ms
    requests: List[dict] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# SSH helper — runs commands on the Raspberry Pi
# ─────────────────────────────────────────────────────────────

class SSHRunner:
    def __init__(self, host: str, user: str, key_path: str):
        self.host     = host
        self.user     = user
        self.key_path = key_path
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.host, username=self.user, key_filename=self.key_path)
        self._client = client
        print(f"[SSH] Connected to {self.user}@{self.host}")

    def disconnect(self):
        if self._client:
            self._client.close()
            self._client = None
            print("[SSH] Disconnected")

    def run(self, cmd: str, timeout: int = 120) -> Tuple[str, str, int]:
        """Run a command and wait for it to finish. Returns (stdout, stderr, exit_code)."""
        _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        return stdout.read().decode(), stderr.read().decode(), exit_code

    def run_background(self, cmd: str) -> paramiko.Channel:
        """Start a command in background without waiting for it to finish."""
        transport = self._client.get_transport()
        channel   = transport.open_session()
        channel.exec_command(cmd)
        return channel


class LocalRunner:
    """Drop-in replacement for SSHRunner that runs commands locally via subprocess.
    Use when the script is executed directly on the RPi (RPI_LOCAL = True).
    """

    def connect(self):
        print("[Local] Running iperf3 commands directly on this machine")

    def disconnect(self):
        pass

    def run(self, cmd: str, timeout: int = 120) -> Tuple[str, str, int]:
        """Run a command locally and wait for it to finish."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1

    def run_background(self, cmd: str) -> subprocess.Popen:
        """Start a command locally in background (fire-and-forget)."""
        return subprocess.Popen(
            cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )


# ─────────────────────────────────────────────────────────────
# iPerf3 measurement
# ─────────────────────────────────────────────────────────────

def run_iperf_sample(
    ssh: SSHRunner,
    server: str,
    duration: int = 2,
    reverse: bool = False,
) -> Optional[float]:
    """
    Run a single iperf3 test from the RPi.

    reverse=False → RPi sends to server   = Uplink   (UL)
    reverse=True  → RPi receives from server = Downlink (DL)

    Returns throughput in Mbps, or None on failure.
    """
    reverse_flag = "-R" if reverse else ""
    cmd = f"iperf3 -c {server} -B {UE_PRIVATE_IP} -t {duration} {reverse_flag} -J --connect-timeout 3000"
    stdout, stderr, code = ssh.run(cmd, timeout=duration + 10)

    if code != 0:
        direction = "DL" if reverse else "UL"
        print(f"[iperf3-{direction}] Error (exit {code}): {stderr.strip()[:120]}")
        return None

    try:
        data = json.loads(stdout)
        # For reverse (-R): RPi is receiver → use sum_received
        # For normal:        RPi is sender   → use sum_sent
        key = "sum_received" if reverse else "sum_sent"
        bits_per_sec = data["end"][key]["bits_per_second"]
        return round(bits_per_sec / 1_000_000, 2)
    except Exception as e:
        print(f"[iperf3] JSON parse error: {e}")
        return None


def collect_sample(ssh: SSHRunner, server: str, qos_thresholds: dict) -> Sample:
    """
    Collect one DL + UL measurement sample from the RPi.
    Each call takes approximately (2 × iperf_duration) seconds.
    """
    # Downlink: server → RPi  (reverse flag)
    dl = run_iperf_sample(ssh, server, duration=TC1_IPERF_DURATION, reverse=True)
    # Brief pause so the iperf3 server closes the DL connection before UL starts
    time.sleep(1)
    # Uplink:   RPi → server  (normal)
    ul = run_iperf_sample(ssh, server, duration=TC1_IPERF_DURATION, reverse=False)

    dl_mbps = dl if dl is not None else 0.0
    ul_mbps = ul if ul is not None else 0.0

    qos_ok = (
        0 < dl_mbps <= qos_thresholds["max_dl_mbps"]
        and 0 < ul_mbps <= qos_thresholds["max_ul_mbps"]
    )

    return Sample(
        timestamp=time.time(),
        dl_mbps=dl_mbps,
        ul_mbps=ul_mbps,
        qos_ok=qos_ok,
    )


# ─────────────────────────────────────────────────────────────
# QoD API client
# ─────────────────────────────────────────────────────────────

# Persistent HTTP session — reuses TCP connections across all QoD calls,
# eliminating per-request handshake overhead (~30-80 ms each).
_http = requests.Session()

def build_session_payload(
    ue_public_ip: str,
    ue_private_ip: str,
    app_server_cidr: str,
    qos_profile: str,
    duration: int,
) -> Dict[str, Any]:
    return {
        "device": {
            "ipv4Address": {
                "publicAddress": ue_public_ip,
                "privateAddress": ue_private_ip,
            }
        },
        "applicationServer": {
            "ipv4Address": app_server_cidr,
        },
        "qosProfile": qos_profile,
        "duration": duration,
    }


def create_qod_session(
    payload: Dict[str, Any],
    sessions_url: str = QOD_SESSIONS,
) -> ApiResult:
    """POST /sessions and measure establishment time."""
    t0 = time.perf_counter()
    try:
        resp = _http.post(sessions_url, json=payload, timeout=10)
        t1   = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000.0

        success = resp.status_code == 201
        body: Dict[str, Any] = {}
        try:
            body = resp.json()
        except Exception:
            pass

        return ApiResult(
            request_index=0,
            success=success,
            status_code=resp.status_code,
            establishment_time_ms=round(elapsed_ms, 2),
            session_id=str(body.get("sessionId")) if success else None,
            qos_status=body.get("qosStatus") if success else None,
            error=None if success else str(body),
        )

    except Exception as e:
        t1 = time.perf_counter()
        return ApiResult(
            request_index=0,
            success=False,
            status_code=0,
            establishment_time_ms=round((t1 - t0) * 1000.0, 2),
            session_id=None,
            qos_status=None,
            error=str(e),
        )


def delete_qod_session(session_id: str, sessions_url: str = QOD_SESSIONS):
    """DELETE /sessions/{session_id} to clean up after each test."""
    try:
        resp = _http.delete(f"{sessions_url}/{session_id}", timeout=30)
        if resp.status_code == 204:
            print(f"[QoD] Session {session_id} deleted")
        else:
            print(f"[QoD] Delete returned {resp.status_code} for session {session_id}")
    except Exception as e:
        print(f"[QoD] Failed to delete session {session_id}: {e}")


def poll_qod_session_status(
    session_id: str,
    sessions_url: str = QOD_SESSIONS,
    target_status: str = "AVAILABLE",
    poll_interval: float = 2.0,
    timeout: float = 45.0,
) -> Optional[str]:
    """
    Poll GET /sessions/{session_id} until qosStatus reaches target_status
    or times out.  Returns the final qosStatus string (or None on error).
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = _http.get(f"{sessions_url}/{session_id}", timeout=5)
            if resp.status_code == 200:
                status = resp.json().get("qosStatus", "")
                print(f"[QoD] qosStatus = {status}")
                if target_status.upper() in str(status).upper():
                    return status
                if "UNAVAILABLE" in str(status).upper():
                    print(f"[QoD] Session became UNAVAILABLE — network did not grant QoS")
                    return status
        except Exception as e:
            print(f"[QoD] Poll error: {e}")
        time.sleep(poll_interval)
    print(f"[QoD] Timed out waiting for qosStatus={target_status} after {timeout}s")
    return None


# ─────────────────────────────────────────────────────────────
# Background traffic (iPerf3 on RPi)
# ─────────────────────────────────────────────────────────────

def ensure_bg_server_running(port: int = IPERF_BG_PORT) -> bool:
    """
    If IPERF_SERVER_SSH_USER is set, SSH into the iperf3 server and start
    a background iperf3 server instance on the given port if not already running.
    Returns True if the server is (or becomes) available, False otherwise.
    """
    if not IPERF_SERVER_SSH_USER:
        return True  # assume it's running; check_bg_server_reachable will catch it

    srv_ssh = SSHRunner(IPERF_SERVER, IPERF_SERVER_SSH_USER, IPERF_SERVER_SSH_KEY)
    try:
        srv_ssh.connect()
        # Check if already listening
        _, _, code = srv_ssh.run(f"ss -tlnp | grep ':{port} '|| ss -ulnp | grep ':{port} '", timeout=5)
        if code == 0:
            print(f"[BG Server] iperf3 already listening on port {port} ✅")
            return True
        # Not running — start it
        srv_ssh.run_background(f"iperf3 -s -p {port} -D --logfile /tmp/iperf3-bg-{port}.log")
        time.sleep(1)
        # Verify it started
        _, _, code = srv_ssh.run(f"ss -tlnp | grep ':{port} ' || ss -ulnp | grep ':{port} '", timeout=5)
        if code == 0:
            print(f"[BG Server] Started iperf3 -s -p {port} on {IPERF_SERVER} ✅")
            return True
        print(f"[BG Server] ⚠️  Failed to start iperf3 on port {port} — check {IPERF_SERVER}")
        return False
    except Exception as e:
        print(f"[BG Server] ⚠️  SSH to {IPERF_SERVER} failed: {e}")
        return False
    finally:
        srv_ssh.disconnect()


def check_bg_server_reachable(ssh: SSHRunner, server: str, port: int = IPERF_BG_PORT) -> bool:
    """
    Quick 2-second UDP probe to verify the BG iperf3 server is reachable.
    Returns True if the server responds, False if connection is refused/timeout.
    """
    cmd = (
        f"iperf3 -c {server} -B {UE_PRIVATE_IP} -p {port}"
        f" -t 2 -b 1M -u -J --connect-timeout 3000"
    )
    _, stderr, code = ssh.run(cmd, timeout=10)
    if code != 0:
        print(f"[BG Traffic] ⚠️  Server unreachable on port {port}: {stderr.strip()[:100]}")
        print(f"[BG Traffic] ⚠️  Start it on {server} with:  iperf3 -s -p {port} -D")
        return False
    return True


def start_background_traffic(
    ssh: SSHRunner,
    server: str,
    bitrate: str,
    duration: int,
    num_streams: int,
    port: int = IPERF_BG_PORT,
) -> None:
    """
    Start a single iPerf3 UDP session with num_streams parallel streams (-P)
    on the RPi to saturate radio capacity.  Uses -R (reverse) so the server
    sends to the RPi (DL direction) — avoids competing with the UL measurement
    probe which would otherwise starve to 0 on limited 5G UL capacity.
    Runs non-blocking (fire and forget).
    """
    total_bitrate = f"{int(bitrate.rstrip('MmKk')) * num_streams}M"
    cmd = (
        f"iperf3 -c {server} -B {UE_PRIVATE_IP} -p {port}"
        f" -t {duration} -b {bitrate} -P {num_streams} -u -R"
    )
    ssh.run_background(cmd)
    print(f"[BG Traffic] Started: -P {num_streams} streams × {bitrate} = {total_bitrate} total DL (port={port})")


# ─────────────────────────────────────────────────────────────
# KPI calculations
# ─────────────────────────────────────────────────────────────

def percentile(data: List[float], p: float) -> float:
    if not data:
        return 0.0
    s  = sorted(data)
    k  = (len(s) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 2)


def compute_retainability(scenario: str, samples: List[Sample]) -> RetainabilityResult:
    total   = len(samples)
    ok      = sum(1 for s in samples if s.qos_ok)
    ret_pct = round((ok / total * 100), 2) if total > 0 else 0.0

    dl_vals = [s.dl_mbps for s in samples]
    ul_vals = [s.ul_mbps for s in samples]

    return RetainabilityResult(
        scenario=scenario,
        qos_profile=QOS_PROFILE,
        total_samples=total,
        qos_ok_samples=ok,
        retainability_pct=ret_pct,
        avg_dl_mbps=round(statistics.mean(dl_vals), 2) if dl_vals else 0.0,
        min_dl_mbps=round(min(dl_vals), 2) if dl_vals else 0.0,
        max_dl_mbps=round(max(dl_vals), 2) if dl_vals else 0.0,
        p95_dl_mbps=percentile(dl_vals, 95),
        stdev_dl_mbps=round(statistics.stdev(dl_vals), 2) if len(dl_vals) > 1 else 0.0,
        avg_ul_mbps=round(statistics.mean(ul_vals), 2) if ul_vals else 0.0,
        min_ul_mbps=round(min(ul_vals), 2) if ul_vals else 0.0,
        max_ul_mbps=round(max(ul_vals), 2) if ul_vals else 0.0,
        p95_ul_mbps=percentile(ul_vals, 95),
        stdev_ul_mbps=round(statistics.stdev(ul_vals), 2) if len(ul_vals) > 1 else 0.0,
        threshold_met=ret_pct >= RETAINABILITY_THRESHOLD_PCT,
        samples=[asdict(s) for s in samples],
    )


def compute_api_kpis(scenario: str, results: List[ApiResult], concurrent_hz: float = 0.0) -> ApiKpiResult:
    total = len(results)
    succ  = sum(1 for r in results if r.success)
    # Establishment time is only meaningful for SUCCESSFUL requests (spec §TC_QoD_2).
    # Failed requests reflect error-handling latency, not provisioning performance.
    succ_times = [r.establishment_time_ms for r in results if r.success]

    success_rate = round((succ / total * 100), 3) if total > 0 else 0.0
    avg_t  = round(statistics.mean(succ_times), 2) if succ_times else 0.0
    min_t  = round(min(succ_times), 2) if succ_times else 0.0
    p50_t  = percentile(succ_times, 50)
    p95_t  = percentile(succ_times, 95)
    max_t  = round(max(succ_times), 2) if succ_times else 0.0
    std_t  = round(statistics.stdev(succ_times), 2) if len(succ_times) > 1 else 0.0

    return ApiKpiResult(
        scenario=scenario,
        concurrent_hz=concurrent_hz,
        total_requests=total,
        successful=succ,
        failed=total - succ,
        success_rate_pct=success_rate,
        avg_establishment_ms=avg_t,
        min_establishment_ms=min_t,
        p50_establishment_ms=p50_t,
        p95_establishment_ms=p95_t,
        max_establishment_ms=max_t,
        stdev_establishment_ms=std_t,
        success_rate_ok=success_rate >= SUCCESS_RATE_THRESHOLD_PCT,
        establishment_time_ok=max_t < ESTABLISHMENT_TIME_THRESHOLD_MS,
        requests=[asdict(r) for r in results],
    )


# ─────────────────────────────────────────────────────────────
# TC_QoD_1 — QoS Session Retainability
# ─────────────────────────────────────────────────────────────

def run_tc_qod_1_scenario(
    scenario_name: str,
    enable_qod: bool,
    enable_background: bool,
    ssh: SSHRunner,
    baseline_result: Optional["RetainabilityResult"] = None,
) -> RetainabilityResult:

    print(f"\n{'='*60}")
    print(f"[TC_QoD_1] Scenario : {scenario_name}")
    print(f"           QoD      : {'ON' if enable_qod else 'OFF'}")
    print(f"           BG Traffic: {'ON' if enable_background else 'OFF'}")
    print(f"{'='*60}")

    thresholds = QOS_THRESHOLDS[QOS_PROFILE]
    session_id: Optional[str] = None
    samples: List[Sample]     = []

    try:
        # ── Step 1: Apply QoD session ────────────────────────
        if enable_qod:
            print("[TC_QoD_1] Applying QoD session via API...")
            payload = build_session_payload(
                UE_PUBLIC_IP,
                UE_PRIVATE_IP,
                APP_SERVER_CIDR,
                QOS_PROFILE,
                TC1_DURATION_SEC + 60,  # extra margin so session doesn't expire mid-test
            )
            qod_result = create_qod_session(payload)
            if qod_result.success:
                session_id = qod_result.session_id
                print(f"[TC_QoD_1] QoD session created")
                print(f"           sessionId  = {session_id}")
                print(f"           qosStatus  = {qod_result.qos_status}")
                print(f"           est. time  = {qod_result.establishment_time_ms:.1f} ms")
                initial_status = str(qod_result.qos_status or "").upper()
                if "AVAILABLE" in initial_status and "UNAVAILABLE" not in initial_status:
                    print(f"[TC_QoD_1] QoS is ACTIVE in the network ✅ (AVAILABLE on creation)")
                else:
                    print(f"[TC_QoD_1] Waiting for qosStatus=AVAILABLE...")
                    final_status = poll_qod_session_status(session_id)
                    if final_status and "AVAILABLE" in str(final_status).upper() and "UNAVAILABLE" not in str(final_status).upper():
                        print(f"[TC_QoD_1] QoS is ACTIVE in the network ✅")
                    else:
                        print(f"[TC_QoD_1] WARNING: QoS did not become AVAILABLE (status={final_status}) — measurements may not reflect QoS conditions")
            else:
                print(f"[TC_QoD_1] WARNING: QoD session failed → {qod_result.error}")

        # ── Step 2 & 3: BG traffic + measurement loop ─────────
        print(f"\n[TC_QoD_1] Measurement started — window = {TC1_DURATION_SEC}s\n")
        print(f"  {'#':>4}  {'Status':<6}  {'DL (Mbps)':>10}  {'UL (Mbps)':>10}  "
              f"{'DL threshold':>14}  {'UL threshold':>14}")
        print(f"  {'-'*4}  {'-'*6}  {'-'*10}  {'-'*10}  {'-'*14}  {'-'*14}")

        loop_start = time.time()
        end_time   = loop_start + TC1_DURATION_SEC
        sample_num = 0

        # Start BG traffic at full rate before the first sample
        if enable_background:
            if check_bg_server_reachable(ssh, IPERF_SERVER):
                remaining = TC1_DURATION_SEC + 5
                start_background_traffic(
                    ssh, IPERF_SERVER, TC1_IPERF_BITRATE, remaining, TC1_NUM_BG_STREAMS
                )
                print(f"  [▶ BG] {TC1_NUM_BG_STREAMS} streams × {TC1_IPERF_BITRATE} DL — waiting 3s to ramp up")
                time.sleep(3)
            else:
                print(f"[TC_QoD_1] ⚠️  BG traffic skipped — measurements will not reflect congestion")

        while time.time() < end_time:

            sample = collect_sample(ssh, IPERF_SERVER, thresholds)
            samples.append(sample)
            sample_num += 1

            if not enable_qod:
                status = "✅ OK"   # no QoD session → cap not expected → baseline
            else:
                status = "✅ OK  " if sample.qos_ok else "❌ FAIL"
            print(
                f"  [{sample_num:03d}]  {status}  "
                f"{sample.dl_mbps:>10.2f}  "
                f"{sample.ul_mbps:>10.2f}  "
                f"  <= {thresholds['max_dl_mbps']:<11}  "
                f"  <= {thresholds['max_ul_mbps']:<11}"
            )
            if time.time() < end_time:
                time.sleep(TC1_SAMPLE_INTERVAL)

    finally:
        # ── Step 4: Cleanup ───────────────────────────────────
        if session_id:
            delete_qod_session(session_id)

    # ── Step 5: Compute KPI & scenario-specific check ─────────
    result = compute_retainability(scenario_name, samples)
    cap = QOS_THRESHOLDS[QOS_PROFILE]

    if not enable_qod and not enable_background:
        # S1 — Baseline: network must be truly uncapped (DL > cap)
        result.scenario_check_ok   = result.avg_dl_mbps > cap["max_dl_mbps"]
        result.scenario_check_desc = (
            f"Uncapped DL baseline: avg DL {result.avg_dl_mbps} Mbps "
            f"> cap {cap['max_dl_mbps']} Mbps"
        )
    elif not enable_qod and enable_background:
        # S2 — Uncapped under BG traffic: without QoD, DL should exceed the
        # QoS profile cap (confirming no accidental DL shaping).  UL is excluded
        # because 5G UL capacity is naturally asymmetric and may not exceed the
        # cap even without any policy enforcement.
        result.scenario_check_ok   = result.avg_dl_mbps > cap["max_dl_mbps"]
        result.scenario_check_desc = (
            f"Uncapped DL under BG traffic: avg DL {result.avg_dl_mbps:.2f} Mbps"
            f" > {cap['max_dl_mbps']} Mbps cap"
            f" (UL {result.avg_ul_mbps:.2f} Mbps — asymmetric, not checked)"
        )
    else:
        # S3 — QoD active: retainability must reach threshold
        result.scenario_check_ok   = result.threshold_met
        result.scenario_check_desc = (
            f"QoS retainability {result.retainability_pct}% "
            f">= {RETAINABILITY_THRESHOLD_PCT}%"
        )

    verdict_icon = "✅ PASS" if result.scenario_check_ok else "❌ FAIL"
    print(f"\n[TC_QoD_1] {scenario_name}")
    print(f"  {verdict_icon}  {result.scenario_check_desc}")
    if enable_qod:
        print(f"  Retainability = {result.retainability_pct}%  "
              f"(threshold >= {RETAINABILITY_THRESHOLD_PCT}%)")
    print(f"  Avg DL = {result.avg_dl_mbps} Mbps  |  Avg UL = {result.avg_ul_mbps} Mbps")

    return result


# ─────────────────────────────────────────────────────────────
# TC_QoD_2 — Establishment Time + Success Rate
# ─────────────────────────────────────────────────────────────

def _stress_worker(stop_event: threading.Event, rate_hz: float):
    """
    Background thread that fires QoD API requests at a given Hz rate
    to stress the API layer. Uses a non-existing UE to trigger errors
    intentionally (goal is load on the API, not successful QoS).
    """
    interval = 1.0 / rate_hz if rate_hz > 0 else 0.1
    payload  = build_session_payload(
        "10.0.0.99",
        "10.0.0.99",
        "192.168.99.0/24",
        QOS_PROFILE,
        10,
    )
    while not stop_event.is_set():
        try:
            _http.post(QOD_SESSIONS, json=payload, timeout=5)
        except Exception:
            pass
        time.sleep(interval)


def run_tc_qod_2(
    scenario_name: str,
    concurrent_hz: float = 0.0,
) -> ApiKpiResult:

    load_desc = f"{int(concurrent_hz)} Hz concurrent" if concurrent_hz > 0 else "no concurrent load"
    print(f"\n{'='*60}")
    print(f"[TC_QoD_2] Scenario : {scenario_name}")
    print(f"           Load     : {load_desc}")
    print(f"{'='*60}")

    stop_event    = threading.Event()
    stress_threads: List[threading.Thread] = []

    try:
        # ── Step 1: Start stress workers scaled to requested Hz ───
        if concurrent_hz > 0:
            # Scale workers: TC2_WORKERS_PER_10HZ threads per 10 Hz block
            num_workers   = max(1, round(concurrent_hz / 10.0 * TC2_WORKERS_PER_10HZ))
            per_worker_hz = concurrent_hz / num_workers
            for _ in range(num_workers):
                t = threading.Thread(
                    target=_stress_worker,
                    args=(stop_event, per_worker_hz),
                    daemon=True,
                )
                t.start()
                stress_threads.append(t)
            print(f"[TC_QoD_2] {num_workers} stress workers @ {per_worker_hz:.1f} Hz each "
                  f"= {concurrent_hz:.0f} Hz total")
            time.sleep(1)  # let stress ramp up before main requests

        # ── Step 2: Sequential main UE requests ───────────────
        results: List[ApiResult] = []

        print(f"\n[TC_QoD_2] Sending {TC2_NUM_REQUESTS} sequential QoD API requests...\n")
        print(f"  {'#':>4}  {'Status':<6}  {'HTTP':>5}  {'Time (ms)':>10}  "
              f"{'qosStatus':<12}  Session ID")
        print(f"  {'-'*4}  {'-'*6}  {'-'*5}  {'-'*10}  {'-'*12}  {'-'*36}")

        for i in range(TC2_NUM_REQUESTS):
            payload = build_session_payload(
                UE_PUBLIC_IP, UE_PRIVATE_IP, APP_SERVER_CIDR, QOS_PROFILE, 30
            )
            r             = create_qod_session(payload)
            r.request_index = i + 1

            # If the API returned PENDING, poll until AVAILABLE and add that
            # wait time — establishment time = full provisioning time per spec.
            if r.success and r.session_id:
                status_upper = str(r.qos_status or "").upper()
                if "PENDING" in status_upper or "AVAILABLE" not in status_upper:
                    t_poll = time.perf_counter()
                    final_status = poll_qod_session_status(
                        r.session_id, timeout=30.0, poll_interval=0.5
                    )
                    r.establishment_time_ms = round(
                        r.establishment_time_ms + (time.perf_counter() - t_poll) * 1000.0, 2
                    )
                    r.qos_status = final_status
                    r.success    = bool(
                        final_status
                        and "AVAILABLE" in str(final_status).upper()
                        and "UNAVAILABLE" not in str(final_status).upper()
                    )

            results.append(r)

            verdict = "✅ OK " if r.success else "❌ FAIL"
            print(
                f"  [{i+1:03d}]  {verdict}  "
                f"{r.status_code:>5}  "
                f"{r.establishment_time_ms:>10.1f}  "
                f"{str(r.qos_status):<12}  "
                f"{r.session_id or 'N/A'}"
            )

            # Delete successful sessions immediately to avoid resource exhaustion
            if r.session_id:
                delete_qod_session(r.session_id)

            time.sleep(TC2_SEQUENTIAL_DELAY)

    finally:
        # ── Step 3: Stop stress workers ───────────────────────
        stop_event.set()
        for t in stress_threads:
            t.join(timeout=2)

    # ── Step 4: Compute KPIs ──────────────────────────────────
    kpi     = compute_api_kpis(scenario_name, results, concurrent_hz=concurrent_hz)
    sr_v    = "✅ PASS" if kpi.success_rate_ok else "❌ FAIL"
    et_v    = "✅ PASS" if kpi.establishment_time_ok else "❌ FAIL"

    print(f"\n[TC_QoD_2] {scenario_name}")
    print(f"  Success rate     = {kpi.success_rate_pct}%     "
          f"(threshold >= {SUCCESS_RATE_THRESHOLD_PCT}%)   {sr_v}")
    print(f"  Avg est. time    = {kpi.avg_establishment_ms} ms")
    print(f"  P95 est. time    = {kpi.p95_establishment_ms} ms")
    print(f"  Max est. time    = {kpi.max_establishment_ms} ms    "
          f"(threshold < {ESTABLISHMENT_TIME_THRESHOLD_MS} ms)  {et_v}")

    return kpi


# ─────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────

def save_report(
    tc1_results: List[RetainabilityResult],
    tc2_results: List[ApiKpiResult],
):
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "qos_profile": QOS_PROFILE,
        "thresholds_used": {
            "throughput": QOS_THRESHOLDS[QOS_PROFILE],
            "retainability_pct": RETAINABILITY_THRESHOLD_PCT,
            "success_rate_pct": SUCCESS_RATE_THRESHOLD_PCT,
            "establishment_time_ms": ESTABLISHMENT_TIME_THRESHOLD_MS,
        },
        "TC_QoD_1_KPI_Enab_QoD_QoSSessionRetainability": [
            asdict(r) for r in tc1_results
        ],
        "TC_QoD_2_KPI_Enab_QoD_SuccessRate_and_EstablishmentTime": [
            asdict(r) for r in tc2_results
        ],
    }
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n📄 Full report saved → {REPORT_PATH}")

    # ── CSV export ────────────────────────────────────────────
    tc1_fields = [
        "test_case", "scenario", "qos_profile",
        "total_samples", "qos_ok_samples", "retainability_pct",
        "avg_dl_mbps", "min_dl_mbps", "max_dl_mbps", "p95_dl_mbps", "stdev_dl_mbps",
        "avg_ul_mbps", "min_ul_mbps", "max_ul_mbps", "p95_ul_mbps", "stdev_ul_mbps",
        "scenario_check_ok", "scenario_check_desc", "threshold_met",
    ]
    tc2_fields = [
        "test_case", "scenario", "concurrent_hz",
        "total_requests", "successful", "failed", "success_rate_pct",
        "avg_establishment_ms", "min_establishment_ms", "p50_establishment_ms",
        "p95_establishment_ms", "max_establishment_ms", "stdev_establishment_ms",
        "success_rate_ok", "establishment_time_ok",
    ]
    all_fields = list(dict.fromkeys(tc1_fields + tc2_fields))  # preserve order, no dupes

    rows = []
    for r in tc1_results:
        rows.append({
            "test_case":           "TC_QoD_1",
            "scenario":            r.scenario,
            "qos_profile":         r.qos_profile,
            "total_samples":       r.total_samples,
            "qos_ok_samples":      r.qos_ok_samples,
            "retainability_pct":   r.retainability_pct,
            "avg_dl_mbps":         r.avg_dl_mbps,
            "min_dl_mbps":         r.min_dl_mbps,
            "max_dl_mbps":         r.max_dl_mbps,
            "p95_dl_mbps":         r.p95_dl_mbps,
            "stdev_dl_mbps":       r.stdev_dl_mbps,
            "avg_ul_mbps":         r.avg_ul_mbps,
            "min_ul_mbps":         r.min_ul_mbps,
            "max_ul_mbps":         r.max_ul_mbps,
            "p95_ul_mbps":         r.p95_ul_mbps,
            "stdev_ul_mbps":       r.stdev_ul_mbps,
            "scenario_check_ok":   r.scenario_check_ok,
            "scenario_check_desc": r.scenario_check_desc,
            "threshold_met":       r.threshold_met,
        })
    for r in tc2_results:
        rows.append({
            "test_case":              "TC_QoD_2",
            "scenario":               r.scenario,
            "concurrent_hz":          r.concurrent_hz,
            "total_requests":         r.total_requests,
            "successful":             r.successful,
            "failed":                 r.failed,
            "success_rate_pct":       r.success_rate_pct,
            "avg_establishment_ms":   r.avg_establishment_ms,
            "min_establishment_ms":   r.min_establishment_ms,
            "p50_establishment_ms":   r.p50_establishment_ms,
            "p95_establishment_ms":   r.p95_establishment_ms,
            "max_establishment_ms":   r.max_establishment_ms,
            "stdev_establishment_ms": r.stdev_establishment_ms,
            "success_rate_ok":        r.success_rate_ok,
            "establishment_time_ok":  r.establishment_time_ok,
        })

    os.makedirs(os.path.dirname(CSV_REPORT_PATH), exist_ok=True)
    with open(CSV_REPORT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(f"📊 CSV  report saved → {CSV_REPORT_PATH}")


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    print("\n" + "=" * 60)
    print("  QoD KPI Runner")
    print(f"  Profile  : {QOS_PROFILE}")
    print(f"  UE (RPi) : {RPI_HOST}")
    print(f"  QoD API  : {QOD_HOST}")
    print(f"  iPerf srv: {IPERF_SERVER}")
    print("=" * 60)

    # Connect to the RPi — locally if running on the RPi, via SSH otherwise
    if RPI_LOCAL:
        ssh = LocalRunner()
    else:
        ssh = SSHRunner(RPI_HOST, RPI_USER, RPI_SSH_KEY)
    ssh.connect()

    # Ensure the BG iperf3 server is running on port 5202
    ensure_bg_server_running(IPERF_BG_PORT)

    tc1_results: List[RetainabilityResult] = []
    tc2_results: List[ApiKpiResult]        = []

    try:
        # ────────────────────────────────────────────────────
        # TC_QoD_1 — 3 scenarios
        # ────────────────────────────────────────────────────
        scenarios = [
            {
                "name": "1_no_qod_no_background",
                "qod": False,
                "bg":  False,
            },
            {
                "name": "2_no_qod_with_background",
                "qod": False,
                "bg":  True,
            },
            {
                "name": "3_qod_with_background",
                "qod": True,
                "bg":  True,
            },
        ]

        for sc in scenarios:
            # Pass the S1 baseline result to S2 so its congestion check
            # is relative to the actual measured UL capacity, not the QoS cap.
            baseline = tc1_results[0] if tc1_results else None
            result = run_tc_qod_1_scenario(
                scenario_name=sc["name"],
                enable_qod=sc["qod"],
                enable_background=sc["bg"],
                ssh=ssh,
                baseline_result=baseline,
            )
            tc1_results.append(result)
            print("\n[Cooldown] 10s between scenarios...")
            time.sleep(10)

        # ────────────────────────────────────────────────────
        # TC_QoD_2 — Step-increase scalability test
        # Step 0: 0 Hz (baseline), Step 1: +10 Hz, Step 2: +20 Hz ...
        # Stops when KPIs fail OR TC2_MAX_CONCURRENT_HZ is reached.
        # ────────────────────────────────────────────────────
        concurrent_hz = 0.0
        step          = 0
        while True:
            label = (
                f"step{step}_baseline_0Hz"
                if concurrent_hz == 0
                else f"step{step}_{int(concurrent_hz)}Hz_concurrent"
            )
            result = run_tc_qod_2(label, concurrent_hz=concurrent_hz)
            tc2_results.append(result)

            kpis_ok = result.success_rate_ok and result.establishment_time_ok
            if not kpis_ok:
                print(f"\n[TC_QoD_2] ❌ KPIs failed at {concurrent_hz:.0f} Hz — "
                      f"scalability limit reached")
                break

            if concurrent_hz >= TC2_MAX_CONCURRENT_HZ:
                print(f"\n[TC_QoD_2] ✅ All steps passed (0 → {int(concurrent_hz)} Hz)")
                break

            concurrent_hz += TC2_CONCURRENT_STEP_HZ
            step          += 1
            print(f"\n[Cooldown] 10s before step {step} ({int(concurrent_hz)} Hz)...")
            time.sleep(10)

    finally:
        ssh.disconnect()

    # ── Save report ──────────────────────────────────────────
    save_report(tc1_results, tc2_results)

    # ── Final summary ─────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  FINAL KPI SUMMARY")
    print("=" * 60)

    print(f"\n{'─'*60}")
    print(f"  TC_QoD_1 — KPI: QoS Session Retainability  (threshold >= {RETAINABILITY_THRESHOLD_PCT}%)")
    print(f"{'─'*60}")
    print(f"  {'Scenario':<35}  {'Check':<45}  {'Result'}")
    print(f"  {'-'*35}  {'-'*45}  {'-'*8}")
    for r in tc1_results:
        verdict = "✅ PASS" if r.scenario_check_ok else "❌ FAIL"
        print(f"  {r.scenario:<35}  {r.scenario_check_desc:<45}  {verdict}")

    print(f"\n{'─'*60}")
    print(f"  TC_QoD_2 — KPI: Success Rate (>= {SUCCESS_RATE_THRESHOLD_PCT}%)  "
          f"& Est. Time (< {ESTABLISHMENT_TIME_THRESHOLD_MS:.0f} ms)")
    print(f"{'─'*60}")
    print(f"  {'Scenario':<40}  {'Load':>6}  {'SR':>8}  {'SR?':>4}  {'MaxET':>8}  {'ET?'}")
    print(f"  {'-'*40}  {'-'*6}  {'-'*8}  {'-'*4}  {'-'*8}  {'-'*4}")
    for r in tc2_results:
        sr_v = "✅" if r.success_rate_ok else "❌"
        et_v = "✅" if r.establishment_time_ok else "❌"
        print(
            f"  {r.scenario:<40}  "
            f"{r.concurrent_hz:>5.0f}Hz  "
            f"{r.success_rate_pct:>7.3f}%  {sr_v:>4}  "
            f"{r.max_establishment_ms:>7.1f}ms  {et_v}"
        )

    print()


if __name__ == "__main__":
    main()