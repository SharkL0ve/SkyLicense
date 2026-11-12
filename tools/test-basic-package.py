"""Exercise the actual release setup, server, license and customer scripts on Windows."""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import tempfile
import time
import zipfile

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("smoke", REPO / "tools/local-smoke-test.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def main():
    if os.name != "nt":
        raise SystemExit("This verifies Windows PS1 entry points; run the shell entry points on a Linux host separately.")
    root = Path(tempfile.mkdtemp(prefix="SkyLicensePackage-"))
    smoke.private_directory(root)
    package = root / "SkyLicense-Basic"
    with zipfile.ZipFile(REPO / "build/distributions/SkyLicense-Basic-1.0.0.zip") as archive:
        if any(not entry.filename.startswith("SkyLicense-Basic/") or ".." in Path(entry.filename).parts
               for entry in archive.infolist()):
            raise RuntimeError("unexpected release archive path")
        archive.extractall(root)
    password = "Package#" + secrets.token_urlsafe(24)
    password_file = root / "initial-admin.secret"
    smoke.write(password_file, password)
    env = {k: v for k, v in os.environ.items() if not k.startswith("SKYLICENSE_")}
    env["SKYLICENSE_SETUP_ADMIN_PASSWORD_FILE"] = str(password_file)
    run = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(package / "SetupLocal.ps1")],
                         cwd=package, env=env, capture_output=True, timeout=90)
    smoke.write(root / "setup.log", run.stdout + run.stderr)
    if run.returncode:
        raise RuntimeError("release setup failed; inspect private setup.log at " + str(root))
    print("PASS packaged interactive setup entry point (password supplied through private test file)", flush=True)
    env.pop("SKYLICENSE_SETUP_ADMIN_PASSWORD_FILE")
    context = ssl.create_default_context(cafile=str(package / "runtime/certs/auth-chain.pem"))
    api = smoke.Api("https://localhost:18443", context)
    server_log = (root / "server.log").open("wb")
    server = subprocess.Popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(package / "StartServer.ps1")],
                              cwd=package, env=env, stdin=subprocess.PIPE, stdout=server_log, stderr=subprocess.STDOUT)
    client = None
    client_log = None
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if server.poll() is not None:
                raise RuntimeError("packaged server exited before readiness")
            try:
                if api.call("/health/ready")["status"] == "UP":
                    break
            except OSError:
                pass
            time.sleep(0.5)
        else:
            raise RuntimeError("packaged server readiness timeout")
        api.login("admin", password)
        enrollment = api.call("/api/auth/mfa/enrollment", "POST", {"password": password})
        recovery = api.call("/api/auth/mfa/enrollment/confirm", "POST",
                            {"factor": smoke.totp(enrollment["manualSecret"])})["recoveryCodes"]
        api.login("admin", password, recovery.pop())
        program = api.call("/api/programs", "POST", {"name": "DemoApp"})
        boundary = "Package" + secrets.token_hex(12)
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"version\"\r\n\r\n1.0.0\r\n"
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"DemoApp-1.0.0.jar\"\r\nContent-Type: application/java-archive\r\n\r\n").encode()
        body += (package / "DemoApp-1.0.0.jar").read_bytes() + f"\r\n--{boundary}--\r\n".encode()
        api.call(f"/api/programs/{program['id']}/versions", "POST", raw=body,
                 content_type=f"multipart/form-data; boundary={boundary}")
        record = api.call(f"/api/programs/{program['id']}/licenses", "POST", {"bindableIps": 1, "bindableHwids": 1})
        license_run = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(package / "MakeLicense.ps1")],
                                     cwd=package, env=env, input=(record["code"] + "\n").encode(), capture_output=True, timeout=30)
        if license_run.returncode:
            raise RuntimeError("packaged license-file script failed")
        print("PASS packaged server script, MFA, sample upload and license-file script", flush=True)
        client_log = (root / "client.log").open("wb")
        client = subprocess.Popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(package / "StartClient.ps1")],
                                  cwd=package, env=env, stdout=client_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            output = (root / "client.log").read_bytes()
            if b"heartbeat active." in output:
                break
            if client.poll() is not None:
                raise RuntimeError("packaged client failed before ACCEPT")
            time.sleep(0.1)
        else:
            raise RuntimeError("packaged client ACCEPT timeout")
        assert b"Protected DemoApp started successfully." in output
        assert api.call(f"/api/licenses/{record['code']}/logs")["records"][0]["result"] == "OK"
        print("PASS packaged StartClient script, sample entry, ACK and auth_log=OK", flush=True)
        api.call(f"/api/licenses/{record['code']}/ban", "PUT")
        client.wait(timeout=45)
        assert client.returncode == 3
        print("PASS packaged standalone launcher exits after online revocation", flush=True)
    finally:
        if client is not None and client.poll() is None:
            subprocess.run(["taskkill", "/PID", str(client.pid), "/T", "/F"], capture_output=True)
            client.wait()
        if client_log is not None:
            client_log.close()
        if server.poll() is None:
            server.stdin.write(b"stop\n")
            server.stdin.flush()
            try:
                server.wait(timeout=45)
            except subprocess.TimeoutExpired:
                subprocess.run(["taskkill", "/PID", str(server.pid), "/T", "/F"], capture_output=True)
                server.wait()
                raise RuntimeError("packaged server did not stop gracefully")
        server_log.close()
        print("package_test_artifacts=" + str(root), flush=True)
    assert server.returncode == 0
    print("package_smoke=PASS", flush=True)


if __name__ == "__main__":
    main()
