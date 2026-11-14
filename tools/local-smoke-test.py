"""Isolated local HTTPS/API smoke test. Requires Python 3.10+, cryptography, JDK 17+.

Run after Gradle test/bootJar. All writes and credentials are in a new private
temporary directory. No existing deployment/database is touched. The optional
native probe uses the existing SDK resources as-is; failure is reported, never
worked around with a trust-all verifier or a plaintext proxy.
"""
import argparse
import base64
from contextlib import closing
import datetime as dt
import hashlib
import hmac
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

REPO = Path(__file__).resolve().parents[1]


def private_directory(path):
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        quoted = str(path).replace("'", "''")
        command = (
            "$ErrorActionPreference='Stop';"
            "$id=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;"
            f"& icacls '{quoted}' /reset;"
            "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE };"
            f"& icacls '{quoted}' /inheritance:r /grant:r ('*'+$id+':(OI)(CI)F');"
            "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
        )
        subprocess.run(["powershell", "-NoProfile", "-Command", command], check=True,
                       capture_output=True)
    else:
        path.chmod(0o700)


def write(path, value):
    path.write_bytes(value if isinstance(value, bytes) else value.encode("utf-8"))
    if os.name != "nt":
        path.chmod(0o600)


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def tls_material(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(key, hashes.SHA256()))
    write(directory / "auth-chain.pem", cert.public_bytes(serialization.Encoding.PEM))
    write(directory / "auth-key.pem", key.private_bytes(serialization.Encoding.PEM,
          serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


class Api:
    def __init__(self, base, context):
        self.base = base
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=context))
        self.csrf = None

    def call(self, path, method="GET", payload=None, expected=200, raw=None,
             content_type="application/json", csrf=True):
        headers = {"Origin": self.base}
        if self.csrf and csrf:
            headers["X-CSRF-Token"] = self.csrf
        data = raw
        if payload is not None:
            data = json.dumps(payload).encode()
        if data is not None:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        body = response.read()
        if response.code != expected:
            # A response can contain license codes or secrets: do not print it.
            raise RuntimeError(f"API status {response.code}, expected {expected}, method {method}")
        if expected != 200:
            return None
        if "application/json" not in response.headers.get("Content-Type", ""):
            return body
        decoded = json.loads(body)
        if "code" in decoded and decoded["code"] != 200:
            raise RuntimeError(f"API business error {decoded['code']}, method {method}")
        return decoded.get("data", decoded)

    def login(self, username, password, factor=None):
        result = self.call("/api/auth/login", "POST", {"username": username, "password": password})
        if result["mfaRequired"]:
            if factor is None:
                raise RuntimeError("MFA factor required")
            result = self.call("/api/auth/mfa/verify", "POST",
                {"challengeToken": result["challengeToken"], "factor": factor})
        self.csrf = result["csrfToken"]


def totp(secret):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", action="store_true", help="also attempt the existing Windows/Linux SDK library")
    parser.add_argument("--build-native", action="store_true", help="build/sign/harden the current Strict TLS native client using the public CI test identity")
    parser.add_argument("--rust-toolchain", help="optional rustup toolchain override, e.g. nightly")
    parser.add_argument("--native-target", help="optional Rust target triple; Windows defaults to x86_64-pc-windows-msvc")
    parser.add_argument("--basic", action="store_true", help="test the packaged Java-only SDK, including heartbeat and rejection")
    args = parser.parse_args()
    if args.basic and args.native:
        parser.error("choose --basic or --native")
    if args.build_native and not args.native:
        parser.error("--build-native requires --native")
    root = Path(tempfile.mkdtemp(prefix="SkyLicenseSmoke-"))
    private_directory(root)
    deploy = root / "deployment"
    private_directory(deploy)
    for name in ("certs", "resources", "secrets", "fixture", "client", "backups"):
        private_directory(root / name)
    shutil.copy2(REPO / "build/libs/SkyLicense-Server.jar", deploy / "SkyLicense-Server.jar")
    private_directory(deploy / "resources")
    tls_material(root / "certs")
    native_name = "SkyLicense_64.dll" if os.name == "nt" else "libSkyLicense_64.so"
    native_resources = REPO / "Client-Side/src/main/resources"
    if args.build_native:
        native_resources = root / "native-resources"
        private_directory(native_resources)
        build_env = {k: v for k, v in os.environ.items()
                     if not k.startswith("SKYLICENSE_") and k not in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")}
        certificate = x509.load_pem_x509_certificate((root / "certs/auth-chain.pem").read_bytes())
        build_env.update({"SKYLICENSE_MANIFEST_PUBLIC_KEY": "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
                          "SKYLICENSE_BUILD_ID": "09" * 32, "SKYLICENSE_MIN_SECURITY_EPOCH": "1",
                          "SKYLICENSE_SECURITY_EPOCH": "1", "SKYLICENSE_ARTIFACT_CHANNEL": "ci-test",
                          "SKYLICENSE_CERT_SHA256": certificate.fingerprint(hashes.SHA256()).hex()})
        target = args.native_target or ("x86_64-pc-windows-msvc" if os.name == "nt" else None)
        cargo = ["cargo"] + (["+" + args.rust_toolchain] if args.rust_toolchain else [])
        build = cargo + ["build", "--release", "--locked", "--lib", "--bin", "sign_artifact", "--bin", "verify_artifact"]
        if target:
            build += ["--target", target]
        result = subprocess.run(build, cwd=REPO, env=build_env, capture_output=True, timeout=900)
        write(root / "native-build.log", result.stdout + result.stderr)
        if result.returncode:
            print("artifacts=" + str(root), flush=True)
            raise RuntimeError("strict native build failed; inspect private native-build.log")
        output = REPO / "target" / target / "release" if target else REPO / "target/release"
        artifact = output / native_name
        executable = ".exe" if os.name == "nt" else ""
        build_env["SKYLICENSE_MANIFEST_PRIVATE_KEY"] = bytes([7] * 32).hex()  # Public CI test seed, never a production identity.
        result = subprocess.run([str(output / ("sign_artifact" + executable)), str(artifact)],
                                cwd=REPO, env=build_env, capture_output=True, timeout=30)
        write(root / "native-sign.log", result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("native CI manifest signing failed")
        build_env.pop("SKYLICENSE_MANIFEST_PRIVATE_KEY")
        build_env["SKYLICENSE_MANIFEST_VERIFIER"] = str(output / ("verify_artifact" + executable))
        if os.name == "nt":
            verify = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(REPO / "native/tools/verify-pe-hardening.ps1"),
                      "-Path", str(artifact), "-RequireIntegrityManifest"]
        else:
            verify = ["bash", str(REPO / "native/tools/verify-elf-hardening.sh"), str(artifact), "--require-integrity-manifest"]
        result = subprocess.run(verify, cwd=REPO, env=build_env, capture_output=True, timeout=45)
        write(root / "native-hardening.log", result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("native binary/manifest verification failed")
        shutil.copy2(artifact, native_resources / native_name)
        shutil.copy2(str(artifact) + ".integrity", native_resources / (native_name + ".integrity"))
        print("PASS current Strict native release build, signed CI manifest and platform hardening", flush=True)
    build_id, epoch = secrets.token_hex(32), 1
    if args.basic:
        build_id = "7f10d350d700568181fc244d4f3b779c75ab57316ae8e0e573a1802b815c33f0"
    if args.native:
        manifest = (native_resources / (native_name + ".integrity")).read_bytes()
        if len(manifest) != 160 or manifest[:8] != b"SKYINT02":
            raise RuntimeError("existing native manifest is invalid")
        build_id, epoch = manifest[32:64].hex(), struct.unpack(">I", manifest[28:32])[0]
    auth_port, web_port = port(), port()
    config = {"debug": False, "authPort": auth_port, "webPort": web_port,
        "authTlsCertificateChain": str(root / "certs/auth-chain.pem"),
        "authTlsPrivateKey": str(root / "certs/auth-key.pem"), "authTlsServerName": "localhost",
        "minimumClientSecurityEpoch": epoch,
        "allowedClientBuildIds": [build_id], "allowedWebOrigins": []}
    write(deploy / "config.json", json.dumps(config))
    env = {k: v for k, v in os.environ.items() if not k.startswith("SKYLICENSE_")}
    if args.native:
        env["SKYLICENSE_NATIVE_CA_CERT_FILE"] = str(root / "certs/auth-chain.pem")
    password = "Smoke#" + secrets.token_urlsafe(24)
    for name, value in {"OPERATION_LOG_HMAC_KEY": secrets.token_hex(32),
                        "MFA_ENCRYPTION_KEY": secrets.token_hex(32),
                        "BACKUP_HMAC_KEY": secrets.token_hex(32),
                        "LICENSE_FILE_SECRET": secrets.token_hex(32),
                        "BOOTSTRAP_ADMIN_PASSWORD": password}.items():
        file = root / "secrets" / (name.lower() + ".secret")
        write(file, value)
        env["SKYLICENSE_" + name + "_FILE"] = str(file)
    command = ["java", "-XX:+DisableAttachMechanism", "-XX:-EnableDynamicAgentLoading",
               "-jar", str(deploy / "SkyLicense-Server.jar")]
    outcomes = []
    def passed(label):
        outcomes.append(label)
        print("PASS " + label, flush=True)
    def maintenance(*arguments, marker, working=deploy):
        result = subprocess.run(command + list(arguments), cwd=working, env=env,
                                capture_output=True, timeout=90)
        if result.returncode or marker.encode() not in result.stdout:
            write(root / "maintenance-failure.log", result.stdout + result.stderr)
            print("artifacts=" + str(root), flush=True)
            # Fresh preflight has no licenses, sessions or MFA material. Report
            # only exception messages, with every generated credential removed.
            if not (deploy / "web_magiclicense.db").exists():
                diagnostic = (result.stdout + result.stderr).decode("utf-8", errors="replace")
                for secret_file in (root / "secrets").iterdir():
                    value = secret_file.read_text(encoding="utf-8").strip()
                    if value:
                        diagnostic = diagnostic.replace(value, "[redacted]")
                errors = [line.strip() for line in diagnostic.splitlines()
                          if re.search(r"Exception(?: in thread|:)|Error:|Caused by:", line)]
                for error in errors[:6]:
                    print("maintenance_error=" + error[:1_000], flush=True)
            raise RuntimeError("maintenance failed; inspect private maintenance-failure.log")
    maintenance("--validate-config", marker="deployment_validation=ok")
    passed("fresh deployment preflight")
    context = ssl.create_default_context(cafile=str(root / "certs/auth-chain.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    api = Api(f"https://localhost:{web_port}", context)
    process = None
    log = (root / "server.log").open("wb")
    def start(working=deploy):
        nonlocal process
        process = subprocess.Popen(command, cwd=working, env=env, stdin=subprocess.PIPE,
                                   stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("server exited; inspect private server.log")
            try:
                if api.call("/health/ready")["status"] == "UP":
                    return
            except (OSError, RuntimeError):
                pass
            time.sleep(0.5)
        raise RuntimeError("server readiness timeout")
    def stop():
        if process is not None and process.poll() is None:
            process.stdin.write(b"stop\n")
            process.stdin.flush()
            try:
                process.wait(timeout=40)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise RuntimeError("server did not stop gracefully")
            if process.returncode:
                raise RuntimeError("server shutdown failed")
    native_ok = None
    basic_ok = None
    try:
        start()
        passed("TLS 1.3 startup and readiness")
        assert api.call("/health/live")["status"] == "UP"
        assert b"SkyLicense" in api.call("/")
        with context.wrap_socket(socket.create_connection(("localhost", auth_port)), server_hostname="localhost") as stream:
            assert stream.version() == "TLSv1.3"
        passed("Web index and native TLS listener")
        api.call("/api/programs", expected=401)
        api.login("admin", password)
        api.call("/api/programs", expected=403)
        enrollment = api.call("/api/auth/mfa/enrollment", "POST", {"password": password})
        recovery = api.call("/api/auth/mfa/enrollment/confirm", "POST",
                            {"factor": totp(enrollment["manualSecret"])})["recoveryCodes"]
        api.login("admin", password, recovery.pop())
        passed("bootstrap login, MFA enforcement, enrollment and recovery-code login")
        api.call("/api/programs", "POST", {"name": "NoCsrf"}, expected=403, csrf=False)
        user_password = "User#" + secrets.token_urlsafe(24)
        user = api.call("/api/users", "POST", {"username": "smokeuser", "password": user_password,
                        "role": "USER", "maxPrograms": 2})
        ordinary = Api(api.base, context)
        ordinary.login("smokeuser", user_password)
        ordinary.call("/api/users", expected=403)
        program = ordinary.call("/api/programs", "POST", {"name": "LocalSmoke", "description": "isolated smoke fixture"})
        pid = program["id"]
        passed("CSRF rejection, user creation and role isolation")
        fixture = root / "fixture"
        shutil.copy2(REPO / "tools/fixtures/SmokeEntry.java", fixture / "SmokeEntry.java")
        subprocess.run(["javac", "--release", "17", str(fixture / "SmokeEntry.java")], check=True, capture_output=True)
        jar = fixture / "protected.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            archive.writestr("settings.yml", "Name: LocalSmoke\nVersion: 1.0.0\nEntryClass: SmokeEntry\nEntryPoint: start\nInfPort: false\nKeepClasses: []\n")
            for class_file in fixture.glob("SmokeEntry*.class"):
                archive.write(class_file, class_file.name)
        boundary = "Smoke" + secrets.token_hex(12)
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"version\"\r\n\r\n1.0.0\r\n"
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"protected.jar\"\r\nContent-Type: application/java-archive\r\n\r\n").encode() + jar.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
        ordinary.call(f"/api/programs/{pid}/versions", "POST", raw=body, content_type=f"multipart/form-data; boundary={boundary}")
        assert len(ordinary.call(f"/api/programs/{pid}/versions")) == 1
        license_record = ordinary.call(f"/api/programs/{pid}/licenses", "POST", {"bindableIps": 1, "bindableHwids": 1, "maxDailyAuth": 10})
        code = license_record["code"]
        api.call(f"/api/licenses/{code}/ban", "PUT", {"reason": "smoke"})
        assert ordinary.call(f"/api/licenses/{code}")["status"] == 0
        api.call(f"/api/licenses/{code}/unban", "PUT")
        assert ordinary.call(f"/api/licenses/{code}")["status"] == 1
        api.call(f"/api/licenses/{code}/unbind", "PUT", {"all": True})
        api.call("/api/admin/reload", "POST")
        passed("protected JAR upload/catalog, license creation, ban/unban, unbind and reload")
        classes = REPO / "Client-Side/build/classes/java/main"
        client = root / "client"
        classpath = os.pathsep.join(map(str, [client, classes, native_resources]))
        result = subprocess.run(["java", "-cp", str(classes), "cn.sky.license.LicenseFileTool", str(client / "license.dat")],
                                input=(code + "\n").encode(), env=env, capture_output=True, timeout=30)
        assert result.returncode == 0 and (client / "license.dat").read_bytes().startswith(b"SKYLIC03")
        passed("customer-specific SKYLIC03 license file generation")
        if args.basic:
            sdk = REPO / "Client-Side/build/libs/SkyLicense-basic.jar"
            basic_cp = os.pathsep.join(map(str, [client, sdk]))
            subprocess.run(["javac", "-cp", str(sdk), "-d", str(client), str(REPO / "tools/BasicSmokeClient.java")], check=True, capture_output=True)
            env["SKYLICENSE_BASIC_CA_CERT_FILE"] = str(root / "certs/auth-chain.pem")
            probe = ["java", "-cp", basic_cp, "BasicSmokeClient", str(client / "data"), f"localhost:{auth_port}"]
            result = subprocess.run(probe + ["accept"], env=env, capture_output=True, timeout=75)
            write(root / "basic-probe.log", result.stdout + result.stderr)
            if result.returncode or not all(marker in result.stdout for marker in (
                    b"basic_accept=true", b"entry_started=true", b"heartbeat_window_completed=true")):
                raise RuntimeError("basic SDK end-to-end failed; inspect private basic-probe.log")
            passed("packaged basic SDK authentication, transformed entry, ACK and real heartbeats")
            history = ordinary.call(f"/api/licenses/{code}/logs")
            assert history["records"][0]["result"] == "OK"
            def rejected(label, expected, data_dir=None):
                candidate = list(probe)
                if data_dir is not None:
                    candidate[-2] = str(data_dir)
                run = subprocess.run(candidate + ["reject:" + expected], env=env,
                                     capture_output=True, timeout=45)
                write(root / ("basic-reject-" + label + ".log"), run.stdout + run.stderr)
                if run.returncode or b"rejection_confirmed=true" not in run.stdout:
                    raise RuntimeError("basic SDK rejection check failed: " + label)
            api.call(f"/api/licenses/{code}/ban", "PUT")
            rejected("ban", "BLACKLIST")
            api.call(f"/api/licenses/{code}/unban", "PUT")
            ordinary.call(f"/api/licenses/{code}", "PUT", {
                "expirationDate": (dt.datetime.now() - dt.timedelta(days=1)).strftime("%Y-%m-%d-%H:%M")})
            rejected("expiry", "BLACKLIST")
            ordinary.call(f"/api/licenses/{code}", "PUT", {"expirationDate": "", "maxDailyAuth": 1})
            rejected("daily-quota", "DAILY_AUTH_LIMIT")
            ordinary.call(f"/api/licenses/{code}", "PUT", {"maxDailyAuth": 100})
            rejected("installation-binding", "NOT_ADDRESS", client / "other-installation")
            env["SKYLICENSE_BASIC_CERT_SHA256"] = "00" * 32
            rejected("bad-tls-pin", "SOCKET_ERROR_CONNECT")
            env.pop("SKYLICENSE_BASIC_CERT_SHA256")
            passed("basic SDK rejects banned/expired/quota-exceeded/other-installation licenses and wrong TLS pin")
            revoke_log = (root / "basic-revocation.log").open("wb")
            running = subprocess.Popen(probe + ["revoke"], env=env, stdout=revoke_log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if b"ready_for_revocation=true" in (root / "basic-revocation.log").read_bytes():
                        break
                    if running.poll() is not None:
                        raise RuntimeError("revocation probe exited before authentication")
                    time.sleep(0.1)
                else:
                    raise RuntimeError("revocation probe authentication timeout")
                api.call(f"/api/licenses/{code}/ban", "PUT")
                running.wait(timeout=50)
                if running.returncode:
                    raise RuntimeError("running basic SDK did not revoke its session")
            finally:
                if running.poll() is None:
                    running.kill()
                    running.wait()
                revoke_log.close()
            assert b"revocation_confirmed=true" in (root / "basic-revocation.log").read_bytes()
            api.call(f"/api/licenses/{code}/unban", "PUT")
            passed("live license ban causes signed heartbeat revocation and host disable callback")
            basic_ok = True
        if args.native:
            subprocess.run(["javac", "-cp", str(classes), "-d", str(client), str(REPO / "tools/LocalSmokeClient.java"),
                            str(REPO / "native/tests/NativeLoadSmoke.java")], check=True, capture_output=True)
            jvm = ["java", "-XX:+DisableAttachMechanism", "-XX:-EnableDynamicAgentLoading", "-cp", classpath]
            probe = jvm + ["LocalSmokeClient", str(client / "data"), f"localhost:{auth_port}"]
            result = subprocess.run(probe + ["accept"], env=env, capture_output=True, timeout=75)
            write(root / "native-probe.log", result.stdout + result.stderr)
            with closing(sqlite3.connect(deploy / "web_magiclicense.db")) as database:
                last = database.execute("SELECT result FROM auth_log ORDER BY id DESC LIMIT 1").fetchone()
            native_ok = result.returncode == 0 and all(marker in result.stdout for marker in (
                b"native_accept=true", b"entry_started=true", b"heartbeat_window_completed=true",
                b"protected_dispatch_after_rotation=true")) and last == ("OK",)
            if not native_ok:
                raise RuntimeError("native end-to-end failed; inspect private native-probe.log")
            passed("Strict native TLS authentication, transformed entry, ACK, verified heartbeats and repeat-auth rejection")
            def native_rejected(label, expected):
                run = subprocess.run(probe + ["reject:" + expected], env=env, capture_output=True, timeout=45)
                write(root / ("native-reject-" + label + ".log"), run.stdout + run.stderr)
                if run.returncode or b"rejection_confirmed=true" not in run.stdout:
                    raise RuntimeError("native rejection check failed: " + label)
            api.call(f"/api/licenses/{code}/ban", "PUT")
            native_rejected("ban", "BLACKLIST")
            api.call(f"/api/licenses/{code}/unban", "PUT")
            ordinary.call(f"/api/licenses/{code}", "PUT", {
                "expirationDate": (dt.datetime.now() - dt.timedelta(days=1)).strftime("%Y-%m-%d-%H:%M")})
            native_rejected("expiry", "BLACKLIST")
            ordinary.call(f"/api/licenses/{code}", "PUT", {"expirationDate": "", "maxDailyAuth": 1})
            native_rejected("daily-quota", "DAILY_AUTH_LIMIT")
            ordinary.call(f"/api/licenses/{code}", "PUT", {"maxDailyAuth": 100})
            wrong_ca = root / "wrong-ca"
            private_directory(wrong_ca)
            tls_material(wrong_ca)
            env["SKYLICENSE_NATIVE_CA_CERT_FILE"] = str(wrong_ca / "auth-chain.pem")
            native_rejected("untrusted-tls", "SOCKET_ERROR_CONNECT")
            env["SKYLICENSE_NATIVE_CA_CERT_FILE"] = str(root / "certs/auth-chain.pem")
            passed("native rejects banned/expired/quota-exceeded licenses and an untrusted TLS server")
            rejected_dir = root / "rejected-artifacts"
            private_directory(rejected_dir)
            for label in ("unsigned", "tampered-manifest"):
                candidate = rejected_dir / (label + (".dll" if os.name == "nt" else ".so"))
                shutil.copy2(native_resources / native_name, candidate)
                if label == "tampered-manifest":
                    corrupt = bytearray((native_resources / (native_name + ".integrity")).read_bytes())
                    corrupt[-1] ^= 1
                    write(Path(str(candidate) + ".integrity"), bytes(corrupt))
                run = subprocess.run(jvm + ["NativeLoadSmoke", str(candidate)], env=env, capture_output=True, timeout=30)
                write(root / ("native-reject-" + label + ".log"), run.stdout + run.stderr)
                if run.returncode == 0:
                    raise RuntimeError("invalid native artifact was loaded: " + label)
            passed("real JVM refuses native libraries with missing or tampered integrity manifests")
            revoke_log = (root / "native-revocation.log").open("wb")
            running = subprocess.Popen(probe + ["revoke"], env=env, stdout=revoke_log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 40
                while time.monotonic() < deadline:
                    if b"ready_for_revocation=true" in (root / "native-revocation.log").read_bytes():
                        break
                    if running.poll() is not None:
                        raise RuntimeError("native revocation probe exited before authentication")
                    time.sleep(0.1)
                else:
                    raise RuntimeError("native revocation probe authentication timeout")
                api.call(f"/api/licenses/{code}/ban", "PUT")
                running.wait(timeout=65)
                if running.returncode:
                    raise RuntimeError("native revocation did not disable the host")
            finally:
                if running.poll() is None:
                    running.kill()
                    running.wait()
                revoke_log.close()
            output = (root / "native-revocation.log").read_bytes()
            assert b"revocation_confirmed=true" in output and b"revoked_dispatch_blocked=true" in output
            api.call(f"/api/licenses/{code}/unban", "PUT")
            passed("native live revocation disables the Java host and blocks protected method dispatch")
            launcher_log = (root / "native-launcher.log").open("wb")
            launcher = subprocess.Popen(jvm + ["cn.sky.license.NativeLauncher", f"localhost:{auth_port}",
                                        "LocalSmoke", "1.0.0", str(client / "launcher-data")],
                                        env=env, stdout=launcher_log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 40
                while time.monotonic() < deadline:
                    if b"signed native heartbeat active." in (root / "native-launcher.log").read_bytes():
                        break
                    if launcher.poll() is not None:
                        raise RuntimeError("standalone native launcher failed before readiness")
                    time.sleep(0.1)
                else:
                    raise RuntimeError("standalone native launcher readiness timeout")
                api.call(f"/api/licenses/{code}/ban", "PUT")
                launcher.wait(timeout=65)
                if launcher.returncode != 3:
                    raise RuntimeError("standalone native launcher did not exit with revocation status")
            finally:
                if launcher.poll() is None:
                    launcher.kill()
                    launcher.wait()
                launcher_log.close()
            api.call(f"/api/licenses/{code}/unban", "PUT")
            passed("actual NativeLauncher application exits after online license revocation")
        assert api.call("/api/admin/operations/integrity")["verified"]
        passed("operation audit chain integrity")
        env.pop("SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE")
        stop()
        maintenance("--validate-config", marker="deployment_validation=ok")
        backup = root / "backups/local.skybackup"
        maintenance("--create-backup", str(backup), marker="backup_creation=ok")
        maintenance("--verify-backup", str(backup), marker="backup_verification=ok")
        restore = root / "restored"
        maintenance("--extract-backup", str(backup), str(restore), marker="backup_extraction=ok")
        assert (restore / "web_magiclicense.db").is_file()
        with closing(sqlite3.connect(restore / "web_magiclicense.db")) as database:
            assert database.execute("PRAGMA quick_check").fetchone() == ("ok",)
            assert database.execute("PRAGMA foreign_key_check").fetchall() == []
        passed("graceful shutdown, offline backup, verification, extraction and SQLite checks")
        maintenance("--validate-config", marker="deployment_validation=ok", working=restore)
        start(restore)
        assert len(ordinary.call(f"/api/programs/{pid}/versions")) == 1
        assert api.call("/api/admin/operations/integrity")["verified"]
        stop()
        passed("restored deployment preflight, startup, resource catalog and audit chain")
        start()
        assert api.call("/api/auth/session")["user"]["id"] > 0
        assert len(ordinary.call(f"/api/programs/{pid}/versions")) == 1
        assert api.call("/api/admin/operations/integrity")["verified"]
        passed("restart readiness, persistent Web session, resource catalog and audit chain")
    finally:
        stop()
        log.close()
        write(root / "result.json", json.dumps({"passed": outcomes, "native_e2e": native_ok, "basic_e2e": basic_ok,
              "root": str(root)}, ensure_ascii=False, indent=2))
        print("artifacts=" + str(root), flush=True)
    print("web_smoke=PASS", flush=True)
    if args.native and not native_ok:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
