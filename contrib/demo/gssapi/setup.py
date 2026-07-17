#!/usr/bin/env python3
"""Ephemeral Kerberos realm for the akamu tkauth-01 demo.

Modelled after the MIT krb5 k5test.py framework but stripped to the minimum
needed for a local, one-realm demo.  Uses system-installed KDC binaries
(krb5kdc, kdb5_util, kadmin.local).

Usage as a library:
    from setup import Realm
    r = Realm("/tmp/demo-kdc")
    r.start()
    r.addprinc("user@DEMO.TEST", password="secret")
    r.extract_keytab("HTTP/localhost@DEMO.TEST", "/tmp/demo-kdc/idp.keytab")
    ...
    r.stop()

Usage standalone (writes env.sh and stays running until SIGINT):
    python3 setup.py [--testdir /tmp/akamu-demo-kdc]
"""

import atexit
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time

REALM = "DEMO.TEST"
PORTBASE = 62000        # KDC port; must be free on localhost


class Realm:
    def __init__(self, testdir=None, realm=REALM, portbase=PORTBASE):
        self.realm = realm
        self.portbase = portbase
        self.testdir = os.path.abspath(testdir or tempfile.mkdtemp(prefix="akamu-kdc-"))
        self._kdc_proc = None

        # Well-known paths inside testdir
        self.krb5_conf = os.path.join(self.testdir, "krb5.conf")
        self.kdc_conf  = os.path.join(self.testdir, "kdc.conf")
        self.kdc_log   = os.path.join(self.testdir, "kdc.log")
        self.db_path   = os.path.join(self.testdir, "db")
        self.acl_file  = os.path.join(self.testdir, "acl")
        self.stash     = os.path.join(self.testdir, "stash")
        self.ccache    = os.path.join(self.testdir, "ccache")

        os.makedirs(self.testdir, exist_ok=True)

    # ── Environment ──────────────────────────────────────────────────────────

    @property
    def env(self):
        """Subprocess environment that points at this realm's config files."""
        e = os.environ.copy()
        e["KRB5_CONFIG"]      = self.krb5_conf
        e["KRB5_KDC_PROFILE"] = self.kdc_conf
        e["KRB5CCNAME"]       = f"FILE:{self.ccache}"
        e["KRB5RCACHEDIR"]    = self.testdir
        # Make sure tools from the system PATH are accessible
        return e

    # ── Config file generation ───────────────────────────────────────────────

    def _write_configs(self):
        krb5 = textwrap.dedent(f"""\
            [libdefaults]
                default_realm = {self.realm}
                rdns = false
                no_addresses = true
                forwardable = true

            [realms]
                {self.realm} = {{
                    kdc = 127.0.0.1:{self.portbase}
                    admin_server = 127.0.0.1:{self.portbase + 1}
                }}

            [domain_realm]
                localhost = {self.realm}
                127.0.0.1 = {self.realm}
        """)
        kdc = textwrap.dedent(f"""\
            [kdcdefaults]
                kdc_ports = {self.portbase}
                kdc_tcp_ports = {self.portbase}

            [realms]
                {self.realm} = {{
                    database_name = {self.db_path}
                    acl_file = {self.acl_file}
                    key_stash_file = {self.stash}
                    kdc_ports = {self.portbase}
                    kdc_tcp_ports = {self.portbase}
                    max_life = 1h
                    max_renewable_life = 24h
                    supported_enctypes = aes256-cts:normal aes128-cts:normal
                }}

            [logging]
                kdc = FILE:{self.kdc_log}
        """)
        with open(self.krb5_conf, "w") as f:
            f.write(krb5)
        with open(self.kdc_conf, "w") as f:
            f.write(kdc)
        # Stub ACL file (only needed if kadmind is started; we use kadmin.local)
        with open(self.acl_file, "w") as f:
            f.write(f"*/admin@{self.realm} *\n")

    # ── Low-level helpers ────────────────────────────────────────────────────

    def _run(self, *cmd, input=None):
        result = subprocess.run(
            cmd,
            env=self.env,
            input=input,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Command failed: {' '.join(cmd)}\n"
                f"stdout: {result.stdout}\n"
                f"stderr: {result.stderr}"
            )
        return result.stdout

    def _kadmin_local(self, *query):
        """Run a kadmin.local query against the realm database."""
        self._run("kadmin.local", "-r", self.realm, "-q", " ".join(query))

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def create_db(self, master_password="demo-master-pw"):
        """Initialise the KDB with a fresh database and stash file."""
        self._write_configs()
        self._run(
            "kdb5_util", "create", "-r", self.realm,
            "-s",               # create stash file
            "-P", master_password,
        )

    def start(self, master_password="demo-master-pw"):
        """Create the database (if not already done) and start krb5kdc."""
        if not os.path.exists(self.db_path + ".db") and not os.path.exists(self.db_path):
            self.create_db(master_password)

        log_fd = open(self.kdc_log, "a")
        self._kdc_proc = subprocess.Popen(
            ["krb5kdc", "-n", "-r", self.realm],
            env=self.env,
            stdout=log_fd,
            stderr=log_fd,
        )
        # Wait until the KDC is actually listening
        self._wait_for_kdc()
        atexit.register(self.stop)
        print(f"[setup] KDC started (pid {self._kdc_proc.pid}) listening on port {self.portbase}",
              file=sys.stderr)

    def _wait_for_kdc(self, timeout=10):
        import socket
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._kdc_proc.poll() is not None:
                raise RuntimeError("krb5kdc exited immediately; check " + self.kdc_log)
            try:
                with socket.create_connection(("127.0.0.1", self.portbase), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(f"KDC not listening after {timeout}s; see {self.kdc_log}")

    def stop(self):
        if self._kdc_proc and self._kdc_proc.poll() is None:
            self._kdc_proc.terminate()
            try:
                self._kdc_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._kdc_proc.kill()
            print("[setup] KDC stopped", file=sys.stderr)
        self._kdc_proc = None

    def cleanup(self):
        """Stop KDC and remove the testdir."""
        self.stop()
        shutil.rmtree(self.testdir, ignore_errors=True)

    # ── Principal management ─────────────────────────────────────────────────

    def addprinc(self, name, password=None):
        """Add a principal; generates a random key if password is None."""
        if password is not None:
            self._kadmin_local("addprinc", "-pw", password, name)
        else:
            self._kadmin_local("addprinc", "-randkey", name)

    def extract_keytab(self, princ, keytab):
        """Extract a keytab for princ without re-randomising its key."""
        self._kadmin_local("ktadd", "-k", keytab, "-norandkey", princ)

    def kinit(self, princ, keytab=None, password=None):
        """Obtain a TGT for princ (into self.ccache)."""
        if keytab:
            self._run("kinit", "-k", "-t", keytab, princ)
        elif password is not None:
            self._run("kinit", princ, input=password + "\n")
        else:
            raise ValueError("kinit requires either keytab or password")


# ── Standalone entry point ───────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Start an ephemeral Kerberos realm")
    parser.add_argument("--testdir", default="/tmp/akamu-demo-kdc",
                        help="Directory for KDC files (created if absent)")
    parser.add_argument("--realm", default=REALM)
    parser.add_argument("--portbase", type=int, default=PORTBASE)
    parser.add_argument("--env-file", metavar="FILE",
                        help="Write shell-sourceable env vars to FILE then exit")
    args = parser.parse_args()

    realm = Realm(testdir=args.testdir, realm=args.realm, portbase=args.portbase)
    realm.start()

    # Create demo principals
    user_keytab = os.path.join(args.testdir, "user.keytab")
    idp_keytab  = os.path.join(args.testdir, "idp.keytab")

    realm.addprinc(f"user@{args.realm}", password="demo")
    realm.addprinc(f"HTTP/localhost@{args.realm}")
    realm.addprinc(f"HTTP/127.0.0.1@{args.realm}")
    realm.extract_keytab(f"user@{args.realm}",             user_keytab)
    realm.extract_keytab(f"HTTP/localhost@{args.realm}",   idp_keytab)
    realm.extract_keytab(f"HTTP/127.0.0.1@{args.realm}",  idp_keytab)

    print(f"[setup] user keytab:  {user_keytab}", file=sys.stderr)
    print(f"[setup] IdP  keytab:  {idp_keytab}",  file=sys.stderr)

    env_lines = "\n".join(f'export {k}="{v}"' for k, v in realm.env.items()
                          if k.startswith("KRB5"))
    env_lines += f'\nexport DEMO_USER_KEYTAB="{user_keytab}"'
    env_lines += f'\nexport DEMO_IDP_KEYTAB="{idp_keytab}"'

    env_lines += f'\nexport DEMO_KDC_PID="{os.getpid()}"'

    if args.env_file:
        with open(args.env_file, "w") as f:
            f.write(env_lines + "\n")
        print(f"[setup] env written to {args.env_file}", file=sys.stderr)
        # Fall through to the blocking wait below so the KDC stays alive
        # while this process is running.  The caller (run-demo.sh) sends
        # SIGTERM to us when the demo finishes; our atexit stops the KDC.
        print("[setup] Blocking until signalled (SIGTERM or SIGINT)...", file=sys.stderr)
    else:
        # Interactive mode: print env to stdout
        print("\n# Source these in your shell:")
        print(env_lines)
        print()
        print("[setup] Press Ctrl-C to stop the KDC and clean up", file=sys.stderr)

    def _stop(_sig, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _stop)

    try:
        signal.pause()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        realm.stop()


if __name__ == "__main__":
    main()
