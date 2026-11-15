"""
External records: datasets of splunk/attack_data, pinned by a commit and a sha256,
read as records of the log sources of the rules (detections/external/README.md).

The gate check_external_records.py uses this module. It holds what a later reader
(roadmap item R5) needs too:

  load_sources() / lint_sources()   detections/external/SOURCES.json and its rules
  load_syscalls()                   detections/external/syscalls_x86_64.json
  Cache, obtain()                   the content-addressed cache and the fixed origins
  check_yml()                       a dataset's yml at the commit against its entry
  check_procedure()                 its procedure label against the yml and the
                                    titles and cve.* tags of the rules of its technique
  read_dataset()                    the loader of each format: one Record for each
                                    record, routed to a log source by its own shape

Untrusted data. A dataset, a yml, the LICENSE and the kernel's syscall table are
read as bytes, checked against the sha256 that SOURCES.json (or the syscall table)
pins, and only then parsed: JSON with the json module, a yml with yaml.safe_load,
auditd lines and the syscall table with regular expressions. Nothing that the cache
holds is run. A file name in the cache is the sha256 of its bytes, never a path of
the dataset. No message of this module holds a value of a record: a fault names the
dataset, the line or the record and, for a key, the key with repr().
"""

import collections
import glob
import hashlib
import http.client
import json
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request

import auditd_records
import sigma_eval

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SIGMA = os.path.join(HERE, "sigma")
ROOT = os.path.join(HERE, "external")
SOURCES = os.path.join(ROOT, "SOURCES.json")
EXPECTATIONS = os.path.join(ROOT, "expectations.json")
SYSCALLS = os.path.join(ROOT, "syscalls_x86_64.json")
DEFAULT_CACHE = os.path.join("~", ".cache", "det-eng", "external")

REPOSITORY = "splunk/attack_data"
LICENCE = "Apache-2.0"
# The two fixed origins. SOURCES.json holds no URL: each URL is made here from the
# commit and the path. The media host serves the content of a Git LFS file; the raw
# host serves a file that is not in LFS (a yml, the LICENSE) and, for an LFS file,
# its pointer (the oid and the size), which --draft reads.
DATA_ORIGIN = "https://media.githubusercontent.com/media/{repository}/{commit}/{path}"
META_ORIGIN = "https://raw.githubusercontent.com/{repository}/{commit}/{path}"
# The kernel's syscall table, at the tag that syscalls_x86_64.json names.
KERNEL_REPOSITORY = "torvalds/linux"
MAX_BYTES = 50 * 1024 * 1024        # no file larger than this is fetched or read
TIMEOUT = 60                        # seconds, for one request

FORMATS = ("cloudtrail-json", "azure-monitor-json", "k8s-audit-json", "auditd-raw")
PRODUCTS = ("aws", "azure", "gcp", "kubernetes", "linux")
# Azure Monitor / Entra records go to a log source by their own `category`. A record
# of another category (MicrosoftGraphActivityLogs, RiskyUsers, ...) is a record of
# the dataset that no rule of the repository reads.
AZURE_CATEGORIES = {
    "AuditLogs": "auditlogs",
    "SignInLogs": "signinlogs",
    "NonInteractiveUserSignInLogs": "signinlogs",
    "ServicePrincipalSignInLogs": "signinlogs",
    "ManagedIdentitySignInLogs": "signinlogs",
    "Administrative": "activitylogs",
}
X86_64 = "c000003e"                 # the auditd arch of x86_64

COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
TECHNIQUE = re.compile(r"T\d{4}(\.\d{3})?")
CVE = re.compile(r"CVE-\d{4}-\d{4,}")
CVE_TAG = re.compile(r"cve\.(\d{4}-\d{4,})")           # the cve.* tag of a rule
# A path of the repository at the commit: no `..`, no empty part, no leading slash.
PATH = re.compile(r"datasets/[A-Za-z0-9_.()+-]+(/[A-Za-z0-9_.()+-]+)*")
DATA_PATH = re.compile(r"datasets/attack_techniques/(T\d{4}(?:\.\d{3})?)/([A-Za-z0-9_.()+-]+)/"
                       r"([A-Za-z0-9_.()+-]+)")
RAW_AUDIT = re.compile(r"(?:node=\S+ )?type=([A-Z0-9_]+) msg=audit\((\d+)\.(\d+):(\d+)\): ")
DIGITS = re.compile(r"\d+")

Record = collections.namedtuple("Record", "where logsource event")


class Fault(Exception):
    """A structural fault: the run exits 2 in every mode."""


class HashMismatch(Fault):
    """A file whose bytes are not the bytes that the pin names."""


class Unavailable(Exception):
    """A pinned file that could not be read: not in the cache, and no download."""


# ---- SOURCES.json ------------------------------------------------------------------

def dataset_id(path):
    """`<technique>/<directory>/<file stem>` of a data path, or None."""
    m = DATA_PATH.fullmatch(path or "")
    if not m:
        return None
    stem = m.group(3).rsplit(".", 1)[0] if "." in m.group(3) else m.group(3)
    return f"{m.group(1)}/{m.group(2)}/{stem}"


def _path_ok(path):
    return isinstance(path, str) and PATH.fullmatch(path) is not None \
        and ".." not in path.split("/")


def _techniques_ok(value):
    return (isinstance(value, list) and value
            and all(isinstance(t, str) and TECHNIQUE.fullmatch(t) for t in value)
            and len(set(value)) == len(value))


def _text_ok(value):
    return isinstance(value, str) and value.strip() and not value.strip().upper().startswith("TODO")


def _sourcetype_ok(value):
    if isinstance(value, str):
        return bool(value.strip())
    return isinstance(value, list) and value and all(isinstance(v, str) and v for v in value)


DATASET_KEYS = {"id", "path", "sha256", "size", "records", "format", "techniques",
                "sourcetype", "yml", "yml_sha256"}
DATASET_OPTIONAL = {"aliases", "procedure"}
EXCLUDED_KEYS = {"id", "path", "sha256", "size", "techniques", "product", "why"}
EXCLUDED_OPTIONAL = {"aliases", "yml", "yml_sha256"}
TOP_KEYS = {"schema", "repository", "commit", "licence", "licence_file", "licence_sha256",
            "licence_copy", "notice", "datasets", "excluded"}


def _common_entry(where, e, problems, ids, shas):
    """Checks that a dataset entry and an excluded entry share."""
    path = e.get("path")
    if not _path_ok(path) or dataset_id(path) is None:
        problems.append(f"{where}: path {path!r} is not a path of {REPOSITORY} under "
                        "datasets/attack_techniques/<technique>/<directory>/<file>")
    elif e.get("id") != dataset_id(path):
        problems.append(f"{where}: id {e.get('id')!r} is not {dataset_id(path)!r}, the "
                        "<technique>/<directory>/<file stem> of its path")
    if not isinstance(e.get("id"), str):
        problems.append(f"{where}: id {e.get('id')!r} is not text")
    elif e["id"] in ids:
        problems.append(f"{where}: the id {e['id']!r} is listed twice")
    else:
        ids.add(e["id"])
    sha = e.get("sha256")
    if not (isinstance(sha, str) and SHA256.fullmatch(sha)):
        problems.append(f"{where}: sha256 {sha!r} is not 64 lower-case hex digits")
    elif sha in shas:
        problems.append(f"{where}: the sha256 {sha[:12]}... is also the sha256 of "
                        f"{shas[sha]}: list one entry for the bytes, with the other path in "
                        "its `aliases`")
    else:
        shas[sha] = e.get("id")
    size = e.get("size")
    if not (isinstance(size, int) and not isinstance(size, bool) and size > 0):
        problems.append(f"{where}: size {size!r} is not a positive integer")
    elif size > MAX_BYTES:
        problems.append(f"{where}: size {size} is over the cap of {MAX_BYTES} bytes")
    if not _techniques_ok(e.get("techniques")):
        problems.append(f"{where}: techniques {e.get('techniques')!r} is not a list of "
                        "ATT&CK IDs (T1234 or T1234.001), each one time")
    aliases = e.get("aliases", [])
    if not (isinstance(aliases, list) and all(_path_ok(a) and a != path for a in aliases)):
        problems.append(f"{where}: aliases must be a list of other paths of {REPOSITORY}")
    if "yml" in e and not (_path_ok(e["yml"]) and e["yml"].endswith(".yml")):
        problems.append(f"{where}: yml {e['yml']!r} is not the path of a .yml file of "
                        f"{REPOSITORY}")
    if "yml_sha256" in e and not (isinstance(e["yml_sha256"], str)
                                  and SHA256.fullmatch(e["yml_sha256"])):
        problems.append(f"{where}: yml_sha256 is not 64 lower-case hex digits")


def lint_sources(doc, repo=REPO):
    """The problems of a parsed SOURCES.json (structural: each one exits 2)."""
    if not isinstance(doc, dict):
        return ["SOURCES.json: the file is not a JSON object"]
    problems = []
    unknown = sorted(set(doc) - TOP_KEYS)
    missing = sorted(TOP_KEYS - set(doc))
    if unknown or missing:
        problems.append(f"SOURCES.json: unknown key(s) {unknown}, missing key(s) {missing}")
    if doc.get("schema") != 1:
        problems.append(f"SOURCES.json: schema {doc.get('schema')!r} is not 1")
    if doc.get("repository") != REPOSITORY:
        problems.append(f"SOURCES.json: repository {doc.get('repository')!r} is not "
                        f"{REPOSITORY!r}")
    commit = doc.get("commit")
    if not (isinstance(commit, str) and COMMIT.fullmatch(commit)):
        problems.append(f"SOURCES.json: commit {commit!r} is not a full commit SHA (40 "
                        "lower-case hex digits): a branch or a short SHA can change "
                        "what it names")
    if doc.get("licence") != LICENCE:
        problems.append(f"SOURCES.json: licence {doc.get('licence')!r} is not {LICENCE!r}, "
                        "the licence that the owner accepted; a change of licence is the "
                        "owner's decision")
    if doc.get("licence_file") != "LICENSE":
        problems.append("SOURCES.json: licence_file must be 'LICENSE' (the licence file of "
                        f"{REPOSITORY} at the commit)")
    lsha = doc.get("licence_sha256")
    if not (isinstance(lsha, str) and SHA256.fullmatch(lsha)):
        problems.append("SOURCES.json: licence_sha256 is not 64 lower-case hex digits")
    copy = doc.get("licence_copy")
    if not (isinstance(copy, str) and copy.startswith("detections/external/LICENSES/")
            and ".." not in copy.split("/")):
        problems.append(f"SOURCES.json: licence_copy {copy!r} is not a file under "
                        "detections/external/LICENSES/")
    else:
        try:
            with open(os.path.join(repo, copy), "rb") as fh:
                got = hashlib.sha256(fh.read()).hexdigest()
            if got != lsha:
                problems.append(f"SOURCES.json: the licence copy {copy} has sha256 {got}, "
                                f"not the licence_sha256 {lsha}")
        except OSError as e:
            problems.append(f"SOURCES.json: the licence copy {copy} cannot be read "
                            f"({e.strerror})")
    if not isinstance(doc.get("notice"), str):
        problems.append("SOURCES.json: notice must say what NOTICE file the commit holds")
    datasets, excluded = doc.get("datasets"), doc.get("excluded")
    if not isinstance(datasets, list) or not isinstance(excluded, list):
        problems.append("SOURCES.json: datasets and excluded must be lists")
        return problems
    if not datasets:
        problems.append("SOURCES.json lists no dataset: the gate would check nothing")
    ids, shas = set(), {}
    for n, e in enumerate(datasets, 1):
        where = f"SOURCES.json datasets[{n}]"
        if not isinstance(e, dict):
            problems.append(f"{where}: not an object")
            continue
        keys = set(e)
        if not DATASET_KEYS <= keys or keys - DATASET_KEYS - DATASET_OPTIONAL:
            problems.append(f"{where}: missing key(s) {sorted(DATASET_KEYS - keys)}, unknown "
                            f"key(s) {sorted(keys - DATASET_KEYS - DATASET_OPTIONAL)}")
            continue
        where = f"SOURCES.json dataset {e.get('id')!r}"
        _common_entry(where, e, problems, ids, shas)
        records = e.get("records")
        if not (isinstance(records, int) and not isinstance(records, bool) and records > 0):
            problems.append(f"{where}: records {records!r} is not a positive integer (the "
                            "number of records that the loader must read)")
        if e.get("format") not in FORMATS:
            problems.append(f"{where}: format {e.get('format')!r} is not one of {FORMATS}")
        if not _sourcetype_ok(e.get("sourcetype")):
            problems.append(f"{where}: sourcetype must be the text (or the list) that the yml "
                            "gives")
        proc = e.get("procedure")
        if proc is not None and e.get("format") != "auditd-raw":
            problems.append(f"{where}: a procedure label is for a raw auditd dataset of a CVE "
                            f"exploit; this dataset is {e.get('format')!r}")
        elif proc is not None:
            if not (isinstance(proc, dict) and set(proc) == {"label", "cves", "why"}
                    and _text_ok(proc.get("label")) and _text_ok(proc.get("why"))
                    and isinstance(proc.get("cves"), list) and proc["cves"]
                    and all(isinstance(c, str) and CVE.fullmatch(c) for c in proc["cves"])):
                problems.append(f"{where}: procedure must be {{label, cves, why}}: the CVE or "
                                "exploit name that the yml names, its CVE IDs (CVE-YYYY-N), "
                                "and why")
            elif CVE.fullmatch(" ".join(proc["label"].split())) and \
                    " ".join(proc["label"].split()) not in proc["cves"]:
                problems.append(f"{where}: the procedure label {proc['label']!r} is a CVE ID, "
                                f"and it is not one of the cves {proc['cves']} of the entry")
    for n, e in enumerate(excluded, 1):
        where = f"SOURCES.json excluded[{n}]"
        if not isinstance(e, dict):
            problems.append(f"{where}: not an object")
            continue
        keys = set(e)
        if not EXCLUDED_KEYS <= keys or keys - EXCLUDED_KEYS - EXCLUDED_OPTIONAL:
            problems.append(f"{where}: missing key(s) {sorted(EXCLUDED_KEYS - keys)}, unknown "
                            f"key(s) {sorted(keys - EXCLUDED_KEYS - EXCLUDED_OPTIONAL)}")
            continue
        where = f"SOURCES.json excluded {e.get('id')!r}"
        _common_entry(where, e, problems, ids, shas)
        if e.get("product") not in PRODUCTS:
            problems.append(f"{where}: product {e.get('product')!r} is not one of {PRODUCTS}")
        if not _text_ok(e.get("why")):
            problems.append(f"{where}: why must say why the dataset is left out (not TODO)")
    return problems


def load_json(path, name):
    """A JSON file of the repository, or a Fault that names it."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except OSError as e:
        raise Fault(f"{name}: cannot be read ({e.strerror})") from None
    except UnicodeDecodeError:
        raise Fault(f"{name}: the file is not UTF-8") from None
    except ValueError as e:
        raise Fault(f"{name}: the file is not JSON ({e})") from None


def load_sources(path=SOURCES, repo=REPO):
    doc = load_json(path, "SOURCES.json")
    problems = lint_sources(doc, repo)
    if problems:
        raise Fault("\n".join(problems))
    return doc


# ---- the syscall table -----------------------------------------------------------

def syscall_table_url(source):
    return META_ORIGIN.format(repository=KERNEL_REPOSITORY, commit=source["tag"],
                              path=source["path"])


def derive_syscalls(text, abis):
    """{number (text): name} of the rows of syscall_64.tbl whose ABI is in `abis`."""
    out = {}
    for line in text.split("\n"):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 3 and DIGITS.fullmatch(parts[0]) and parts[1] in abis:
            out[parts[0]] = parts[2]
    return out


def load_syscalls(path=SYSCALLS):
    """(the parsed file, {number: name}); a Fault for a malformed file."""
    doc = load_json(path, "syscalls_x86_64.json")
    problems = []
    src = doc.get("source") if isinstance(doc, dict) else None
    if not (isinstance(doc, dict) and doc.get("schema") == 1 and doc.get("arch") == X86_64
            and isinstance(src, dict) and isinstance(doc.get("syscalls"), dict)):
        raise Fault("syscalls_x86_64.json: wants {schema: 1, arch: 'c000003e', source: {...}, "
                    "syscalls: {number: name}}")
    if set(src) != {"repository", "tag", "path", "sha256", "size", "abis", "licence"}:
        problems.append("syscalls_x86_64.json: source wants the keys repository, tag, path, "
                        "sha256, size, abis and licence")
    if src.get("repository") != KERNEL_REPOSITORY:
        problems.append(f"syscalls_x86_64.json: source repository is not {KERNEL_REPOSITORY!r}")
    if not (isinstance(src.get("tag"), str) and re.fullmatch(r"v\d+\.\d+(\.\d+)?", src["tag"])):
        problems.append(f"syscalls_x86_64.json: source tag {src.get('tag')!r} is not a "
                        "release tag of Linux (v6.18)")
    if src.get("path") != "arch/x86/entry/syscalls/syscall_64.tbl":
        problems.append("syscalls_x86_64.json: source path is not "
                        "arch/x86/entry/syscalls/syscall_64.tbl")
    if not (isinstance(src.get("sha256"), str) and SHA256.fullmatch(src["sha256"])):
        problems.append("syscalls_x86_64.json: source sha256 is not 64 lower-case hex digits")
    if not (isinstance(src.get("size"), int) and 0 < src["size"] <= MAX_BYTES):
        problems.append("syscalls_x86_64.json: source size is not a positive integer")
    if src.get("abis") != ["common", "64"]:
        problems.append("syscalls_x86_64.json: source abis must be ['common', '64']")
    names = {}
    for nr, name in doc["syscalls"].items():
        if not (DIGITS.fullmatch(nr) and isinstance(name, str)
                and re.fullmatch(r"[a-z0-9_]+", name)):
            problems.append(f"syscalls_x86_64.json: {nr!r}: {name!r} is not number: name")
            continue
        names[int(nr)] = name
    if len(set(names.values())) != len(names):
        problems.append("syscalls_x86_64.json: a name is given to two numbers")
    if not names:
        problems.append("syscalls_x86_64.json: the table is empty")
    if problems:
        raise Fault("\n".join(problems))
    return doc, names


# ---- the cache and the origins ---------------------------------------------------

class Cache:
    """Pinned files by their sha256: <root>/sha256/<hex>. Each read hashes the file
    again; a file whose bytes are not the pinned bytes is deleted."""

    def __init__(self, root):
        self.root = os.path.abspath(os.path.expanduser(root))

    def path(self, sha):
        return os.path.join(self.root, "sha256", sha)

    def read(self, sha, size, what):
        """The bytes, or None when the cache does not hold the file. HashMismatch when
        it holds other bytes (the file is deleted first). size None: the pin names
        no size (a yml, the LICENSE), and only the sha256 is compared."""
        path = self.path(sha)
        if not os.path.lexists(path):
            return None
        try:
            with open(path, "rb") as fh:
                data = fh.read((MAX_BYTES if size is None else size) + 1)
        except OSError as e:
            raise Fault(f"{what}: the cache entry {path} cannot be read ({type(e).__name__}: "
                        f"{e.strerror}); delete it or give another --cache") from None
        got = hashlib.sha256(data).hexdigest()
        if got != sha or (size is not None and len(data) != size):
            try:
                os.remove(path)
            except OSError:
                pass
            raise HashMismatch(f"HASH MISMATCH {what}: the pin is {sha}{_size(size)}; got "
                               f"{got} ({len(data)} bytes) from the cache ({path}); the file "
                               "was deleted")
        return data

    def write(self, sha, data, what):
        """Keep the bytes (already hashed) under their sha256; a Fault that names the
        cache when it cannot."""
        try:
            os.makedirs(os.path.dirname(self.path(sha)), exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix="tmp-", dir=self.root)
        except OSError as e:
            raise Fault(f"{what}: the cache {self.root} cannot keep the file "
                        f"({type(e).__name__}: {e.strerror}); give another --cache") from None
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, self.path(sha))
        except BaseException as e:
            try:
                os.remove(tmp)
            except OSError:
                pass
            if isinstance(e, OSError):
                raise Fault(f"{what}: the cache entry {self.path(sha)} cannot be written "
                            f"({type(e).__name__}: {e.strerror}); delete it or give another "
                            "--cache") from None
            raise


class _SameHost(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to the same scheme and host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if (new.scheme, new.netloc) != (old.scheme, old.netloc):
            raise Unavailable(f"{req.full_url} redirects to another origin "
                              f"({new.scheme + '://' + new.netloc!r}); no redirect off the "
                              "origin is followed")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, limit):
    """At most limit+1 bytes of url (the caller checks the length and the sha256)."""
    opener = urllib.request.build_opener(_SameHost)
    try:
        with opener.open(url, timeout=TIMEOUT) as resp:
            return resp.read(limit + 1)
    except Unavailable:
        raise
    except urllib.error.HTTPError as e:
        raise Unavailable(f"HTTP {e.code} from {url}") from None
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        reason = getattr(e, "reason", None) or e
        raise Unavailable(f"{url}: {type(e).__name__}: {reason}") from None


def data_url(commit, path):
    return DATA_ORIGIN.format(repository=REPOSITORY, commit=commit,
                              path=urllib.parse.quote(path, safe="/"))


def meta_url(commit, path):
    return META_ORIGIN.format(repository=REPOSITORY, commit=commit,
                              path=urllib.parse.quote(path, safe="/"))


def _size(size):
    return "" if size is None else f" ({size} bytes)"


def obtain(cache, sha, size, url, offline, what):
    """(bytes, 'cache' or 'download', HashMismatch of a bad cached copy or None).

    Raises Unavailable when the file is not in the cache and cannot be downloaded,
    and HashMismatch when a download gives other bytes than the pin. size None:
    the pin names only the sha256 (a yml, the LICENSE); at most MAX_BYTES are read."""
    if size is not None and size > MAX_BYTES:
        raise Fault(f"{what}: size {size} is over the cap of {MAX_BYTES} bytes")
    bad = None
    try:
        data = cache.read(sha, size, what)
    except HashMismatch as e:
        data, bad = None, e
    if data is not None:
        return data, "cache", None
    if offline:
        if bad:
            raise bad
        raise Unavailable("not in the cache, and the run is --offline")
    try:
        data = fetch(url, MAX_BYTES if size is None else size)
    except Unavailable as e:
        if bad:                 # the bad copy is the fault, also without a new download
            raise HashMismatch(f"{bad}. A new download failed: {e}") from None
        raise
    got = hashlib.sha256(data).hexdigest()
    if got != sha or (size is not None and len(data) != size):
        raise HashMismatch(f"HASH MISMATCH {what}: the pin is {sha}{_size(size)}; got {got} "
                           f"({len(data)} bytes) from {url}")
    cache.write(sha, data, what)
    return data, "download", bad


def parse_pointer(data):
    """(oid, size) of a Git LFS pointer, or None when the bytes are not a pointer."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    m = re.fullmatch(r"version https://git-lfs\.github\.com/spec/v1\noid sha256:([0-9a-f]{64})\n"
                     r"size (\d+)\n?", text)
    return (m.group(1), int(m.group(2))) if m else None


# ---- the yml of a dataset --------------------------------------------------------

def _as_list(value):
    return [value] if isinstance(value, str) else list(value or [])


def yml_facts(text, path):
    """(techniques, sourcetype, named, description) that a dataset yml gives for
    `path`. description: the text of the yml's `description`, with each run of white
    space as one space ('' when the yml has none)."""
    import yaml

    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise ValueError("the yml is not a mapping")
    techniques = doc.get("mitre_technique")
    description = " ".join(str(doc.get("description") or "").split())
    if isinstance(doc.get("datasets"), list):            # the schema of 2024 and later
        for d in doc["datasets"]:
            if isinstance(d, dict) and str(d.get("path") or "").lstrip("/") == path:
                return _as_list(techniques), _as_list(d.get("sourcetype")), True, description
        return _as_list(techniques), [], False, description
    urls = _as_list(doc.get("dataset"))                  # the old schema: URLs at master
    named = any(isinstance(u, str) and u.endswith("/" + path) for u in urls)
    if not techniques:
        m = DATA_PATH.fullmatch(path)
        techniques = [m.group(1)] if m else []
    return (_as_list(techniques), _as_list(doc.get("sourcetypes") or doc.get("sourcetype")),
            named, description)


def cve_tags(tags):
    """The CVE IDs (CVE-YYYY-N) of the cve.* tags of a rule."""
    return {"CVE-" + m.group(1) for m in map(CVE_TAG.fullmatch, map(str, tags)) if m}


def _bounded(token, text):
    """True when `token` is in `text` with no letter, digit or hyphen right before or
    after it (so "CVE-2026-4350" is not in "CVE-2026-43500", nor "Frag" in "Fragment")."""
    edge = r"(?:[^\W_]|-)"
    return re.search(rf"(?<!{edge}){re.escape(token)}(?!{edge})", text) is not None


def _squeezed(text):
    """The text without white space and letter case: "Copy Fail" is in "(CopyFail ...)"."""
    return "".join(text.split()).casefold()


def technique_rules(techniques, sigma=None):
    """[(rule key, title, CVE IDs)] of each rule file of the technique folders
    (<sigma>/<technique>/*.yml; sigma None: SIGMA, detections/sigma/): the title of its
    first document, and the cve.* tags of all its documents (as
    check_external_records.Rule reads them)."""
    import yaml

    sigma = sigma or SIGMA
    out = []
    for technique in sorted(set(techniques)):
        for path in sorted(glob.glob(os.path.join(sigma, technique, "*.yml"))):
            with open(path, encoding="utf-8") as fh:
                docs = [d for d in yaml.safe_load_all(fh) if isinstance(d, dict)]
            title = next((str(d["title"]) for d in docs if d.get("title")), "")
            tags = [t for d in docs for t in (d.get("tags") or [])]
            out.append((f"{technique}/{os.path.basename(path)}", title, cve_tags(tags)))
    return out


def check_procedure(entry, description, sigma=None):
    """The problems of the procedure label of an entry against the description of its
    yml. A label makes the pair of a rule of another CVE OTHER-PROCEDURE, which no mode
    fails, so it must come from the yml:

      - the label (white space folded) is in the description as a whole token (no
        letter, digit or hyphen next to it);
      - each CVE of `cves` is in the description as a whole token, or it is the cve.*
        tag of a rule of the technique folder whose title holds the label (both
        without white space and letter case: "Copy Fail" and "(CopyFail ...)").

    A label in CVE form must be one of the cves: lint_sources() checks that (offline)."""
    proc = entry.get("procedure") or {}
    label = proc.get("label")
    if label is None:
        return []
    problems, rules = [], None
    folded = " ".join(label.split())
    if not _bounded(folded, description):
        problems.append(f"{entry['id']}: SOURCES.json gives the procedure label {label!r}; the "
                        f"description of the yml {entry['yml']} at the commit does not name it")
    for cve in proc.get("cves") or []:
        if _bounded(cve, description):
            continue
        if rules is None:
            rules = technique_rules(entry["techniques"], sigma)
        if any(cve in cves and _squeezed(folded) in _squeezed(title) for _, title, cves in rules):
            continue
        problems.append(f"{entry['id']}: SOURCES.json gives the procedure label {label!r} the "
                        f"CVE {cve}; the description of the yml {entry['yml']} at the commit "
                        f"does not name the CVE, and no rule of {', '.join(entry['techniques'])} "
                        f"with the tag cve.{cve[len('CVE-'):]} has the label in its title")
    return problems


def check_yml(entry, data, sigma=None):
    """The problems of a dataset entry against the bytes of its yml (already hashed)."""
    try:
        techniques, sourcetype, named, description = yml_facts(data.decode("utf-8"),
                                                               entry["path"])
    except Exception as e:      # noqa: BLE001 (not UTF-8, a YAML error, not a mapping)
        return [f"{entry['id']}: the yml {entry['yml']} cannot be read ({type(e).__name__})"]
    problems = check_procedure(entry, description, sigma)
    if not named:
        problems.append(f"{entry['id']}: the yml {entry['yml']} at the commit does not name "
                        f"the path {entry['path']}")
    # A list prints each value of the yml with repr().
    if sorted(map(str, techniques)) != sorted(entry["techniques"]):
        problems.append(f"{entry['id']}: SOURCES.json pins the techniques "
                        f"{sorted(entry['techniques'])}; the yml at the commit names "
                        f"{sorted(map(str, techniques))}")
    if named and _as_list(entry["sourcetype"]) != [str(s) for s in sourcetype]:
        problems.append(f"{entry['id']}: SOURCES.json pins the sourcetype "
                        f"{entry['sourcetype']!r}; the yml at the commit gives "
                        f"{[str(s) for s in sourcetype]}")
    return problems


# ---- the loaders -----------------------------------------------------------------

def _text(entry_id, data):
    if data.startswith(b"\xef\xbb\xbf"):
        raise Fault(f"{entry_id}: the file starts with a byte order mark (U+FEFF); no "
                    "record of the log sources starts with one")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Fault(f"{entry_id}: the file is not UTF-8 (byte {e.start} is not valid "
                    "UTF-8)") from None


class _NotJSON(Exception):
    """NaN, Infinity or -Infinity (the json module reads them, RFC 8259 has no such
    value), or an integer that one SQLite table cannot hold."""


def _constant(name):
    raise _NotJSON(f"{name}, which is not a JSON value (RFC 8259)")


# The range of an SQLite INTEGER. sigma_eval.EventTable stops with OverflowError on an
# integer outside it.
INT64 = (-2 ** 63, 2 ** 63 - 1)
INT64_DIGITS = len(str(INT64[1]))           # 19: a longer integer is outside the range


def _integer(digits):
    """The parse_int hook of _strict(): the json module gives it the text of each JSON
    integer. A text of more digits than an int64 has is refused before int() reads it
    (int() of a long text is slow, and Python stops at 4300 digits with a ValueError);
    then the value."""
    if len(digits.lstrip("-")) > INT64_DIGITS or not INT64[0] <= int(digits) <= INT64[1]:
        raise _NotJSON("an integer outside the signed 64-bit range of the table (SQLite "
                       "INTEGER)")
    return int(digits)


def _syntax_integer(_digits):
    """The parse_int hook of the shape test: it reads no integer, so no integer can stop
    the test of the shape (the strict parse refuses it with the line)."""
    return 0


class _Twice(dict):
    """A JSON object that holds one key two times. json keeps the last value, and
    another reader can keep the first, so the record is not one record."""
    twice = None


def _pairs(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            out = _Twice(pairs)
            out.twice = key
            return out
        seen.add(key)
    return dict(pairs)


def _strict(text):
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant,
                      parse_int=_integer)


def _json_values(entry_id, text, envelope):
    """[(where, value)]: a JSON array, an envelope {"<envelope>": [...]}, one JSON value
    for the whole file, or one JSON value for each line that is not blank."""
    if not text.strip():
        return []
    try:
        # The shape: one document, or one value for each line.
        json.loads(text, parse_int=_syntax_integer)
    except ValueError:
        pass
    except RecursionError:
        raise Fault(f"{entry_id}: the file nests JSON values too deep to read") from None
    else:
        lines = [n for n, line in enumerate(text.split("\n"), 1) if line.strip()]
        where = f"line {lines[0]}" if len(lines) == 1 else "the JSON document"
        try:
            doc = _strict(text)
        except _NotJSON as e:
            raise Fault(f"{entry_id}: {where} holds {e}") from None
        except ValueError as e:     # a backstop: the shape test read the same text
            raise Fault(f"{entry_id}: {where} is not JSON that the json module reads "
                        f"({type(e).__name__})") from None
        # The document itself (an envelope {"Records": [...]}) must hold each key one
        # time too: json keeps the last list, another reader the first.
        if isinstance(doc, _Twice):
            raise Fault(f"{entry_id}: {where}: an object holds the key {doc.twice!r} two "
                        "times (one reader keeps the first value, another the last)")
        if isinstance(doc, list):
            return [(f"record {n}", v) for n, v in enumerate(doc, 1)]
        if (envelope and isinstance(doc, dict) and set(doc) == {envelope}
                and isinstance(doc[envelope], list)):
            return [(f"record {n}", v) for n, v in enumerate(doc[envelope], 1)]
        return [(f"line {lines[0]}" if len(lines) == 1 else "record 1", doc)]
    out = []
    for n, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            continue
        try:
            out.append((f"line {n}", _strict(line)))
        except _NotJSON as e:
            raise Fault(f"{entry_id}: line {n} holds {e}") from None
        except json.JSONDecodeError as e:
            raise Fault(f"{entry_id}: line {n} is not JSON ({e.msg} at column {e.colno})") \
                from None
        except ValueError as e:     # a backstop: a ValueError that is not a JSONDecodeError
            raise Fault(f"{entry_id}: line {n} is not JSON that the json module reads "
                        f"({type(e).__name__})") from None
        except RecursionError:
            raise Fault(f"{entry_id}: line {n} nests JSON values too deep to read") from None
    return out


def _key_fault(key):
    """Why sigma_eval.EventTable cannot hold this key as a column, or None."""
    if key.lower() == sigma_eval._ROWID:
        return "is the name of the row id of the table (sigma_eval.EventTable)"
    if "\x00" in key:
        return "holds a NUL character (SQLite refuses it in a column name)"
    try:
        key.encode("utf-8")
    except UnicodeEncodeError:
        return "holds a lone surrogate (it is not UTF-8)"
    return None


def _value_fault(value):
    """Why the table cannot hold this value as it is, or None (no value is printed)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if not INT64[0] <= value <= INT64[1]:
            return "holds an integer outside the signed 64-bit range of the table (SQLite INTEGER)"
    elif isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return ("holds a number that is not finite (NaN or an infinity; SQLite keeps "
                    "NaN as NULL)")
    elif isinstance(value, str):
        if "\x00" in value:
            return ("holds text with a NUL character (the text functions of SQLite stop at "
                    "it, so a rule does not see the text after it)")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return "holds text with a lone surrogate (it is not UTF-8)"
    return None


def _shape_fault(value):
    """Why one JSON record is not one record of the log, or None: an object that holds
    a key two times, or two keys that give one field when the record is flattened
    (`{"a.b": 1, "a": {"b": 2}}`; sigma_eval.flatten keeps one of them)."""
    fields, stack = set(), [("", value, True)]
    while stack:
        prefix, node, flat = stack.pop()
        if isinstance(node, list):
            stack.extend(("", item, False) for item in node)
            continue
        if not isinstance(node, dict):
            continue
        if isinstance(node, _Twice):
            return (f"an object holds the key {node.twice!r} two times (one reader keeps the "
                    "first value, another the last)")
        for key, item in node.items():
            name = prefix + key
            if flat and isinstance(item, dict):
                stack.append((name + ".", item, True))
                continue
            if flat:
                if name in fields:
                    return (f"two keys give the field {name!r} when the record is flattened "
                            "(sigma_eval.flatten keeps one of them)")
                fields.add(name)
            stack.append(("", item, False))
    return None


def unstorable(entry_id, records):
    """A Fault for the first key or value of a record that one SQLite table (the table
    of sigma_eval.py that runs the rules) cannot hold as it is. The Fault names the
    record and the key, never the value."""
    for r in records:
        for key, value in r.event.items():
            why = _key_fault(key)
            if why:
                raise Fault(f"{entry_id}: {r.where}: the key {key!r} {why}")
            why = _value_fault(value)
            if why:
                raise Fault(f"{entry_id}: {r.where}: the key {key!r} {why}")


def _cloudtrail(record):
    if isinstance(record.get("eventSource"), str) and isinstance(record.get("eventName"), str):
        return ("aws", "cloudtrail")
    raise ValueError("is not a CloudTrail record (no eventSource and eventName text)")


def _azure(record):
    if isinstance(record.get("category"), str) and isinstance(record.get("operationName"), str):
        service = AZURE_CATEGORIES.get(record["category"])
        return ("azure", service) if service else None
    raise ValueError("is not an Azure Monitor record (no category and operationName text)")


def _k8s(record):
    if record.get("kind") == "Event" and str(record.get("apiVersion", "")).startswith(
            "audit.k8s.io/"):
        return ("kubernetes", "audit")
    raise ValueError("is not a Kubernetes audit event (kind Event, apiVersion audit.k8s.io/*)")


_SHAPES = {"cloudtrail-json": (_cloudtrail, "Records"), "azure-monitor-json": (_azure, None),
           "k8s-audit-json": (_k8s, None)}


def _auditd(entry_id, text, syscalls):
    """Records of a raw auditd log: one event for each SYSCALL record, built by
    auditd_records.syscall_event() as the Linux validator builds it."""
    records, other = [], 0
    for n, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            continue
        m = RAW_AUDIT.match(line)
        if not m:
            raise Fault(f"{entry_id}: line {n} is not a raw auditd record (type=<TYPE> "
                        "msg=audit(<seconds>.<ms>:<serial>): ...)")
        if m.group(1) != "SYSCALL":
            other += 1
            continue
        fields = dict(auditd_records.FIELD.findall(line.partition("\x1d")[0]))
        bad = [k for k in ("syscall", "pid", "ppid") if not DIGITS.fullmatch(fields.get(k, ""))]
        if bad or "arch" not in fields:
            raise Fault(f"{entry_id}: line {n} is a SYSCALL record without "
                        f"{', '.join(bad + ([] if 'arch' in fields else ['arch']))} (a "
                        "decimal number each, and an arch)")
        names = syscalls if fields["arch"] == X86_64 else {}
        try:
            event = auditd_records.syscall_event(line, names)
        except (ValueError, KeyError, AttributeError, OverflowError) as e:
            raise Fault(f"{entry_id}: line {n}: the SYSCALL record cannot be read "
                        f"({type(e).__name__})") from None
        records.append(Record(f"line {n}", ("linux", "auditd"), event))
    return records, other


def read_dataset(entry, data, syscalls):
    """(records, other): the Records of a dataset in its format, and the number of
    records of the log that are not events of the rules' schema (an auditd record of
    another type than SYSCALL). A Fault names a line or a record that is not a record
    of the format, a key or a value that one SQLite table cannot hold, and keys of one
    log source that differ only in letter case."""
    entry_id, fmt = entry["id"], entry["format"]
    text = _text(entry_id, data)
    if fmt == "auditd-raw":
        records, other = _auditd(entry_id, text, syscalls)
    else:
        shape, envelope = _SHAPES[fmt]
        records, other = [], 0
        for where, value in _json_values(entry_id, text, envelope):
            if not isinstance(value, dict):
                raise Fault(f"{entry_id}: {where} is JSON and not an object (a "
                            f"{type(value).__name__})")
            try:
                logsource = shape(value)
            except ValueError as e:
                raise Fault(f"{entry_id}: {where} {e}") from None
            why = _shape_fault(value)
            if why:
                raise Fault(f"{entry_id}: {where}: {why}")
            try:
                event = sigma_eval.flatten(value)
            except RecursionError:
                raise Fault(f"{entry_id}: {where} nests objects too deep to read") from None
            records.append(Record(where, logsource, event))
    unstorable(entry_id, records)
    case_clashes(entry_id, records)
    return records, other


def case_clashes(entry_id, records):
    """A Fault when two keys of the records of one log source differ only in letter
    case: one SQLite table (sigma_eval.EventTable) cannot hold them, and a rule would
    match a key that a case-sensitive SIEM keeps apart."""
    by_source = collections.defaultdict(dict)      # logsource -> folded -> {key: where}
    for r in records:
        if r.logsource is None:
            continue
        folded = by_source[r.logsource]
        for key in r.event:
            folded.setdefault(key.lower(), {}).setdefault(key, r.where)
    problems = []
    for logsource, folded in sorted(by_source.items()):
        for spellings in folded.values():
            if len(spellings) > 1:
                problems.append(" / ".join(f"{k!r} ({w})" for k, w in sorted(spellings.items())))
    if problems:
        raise Fault(f"{entry_id}: keys that differ only in letter case: {'; '.join(problems)}. "
                    "One table cannot hold them, and a rule would match a key that a "
                    "case-sensitive SIEM keeps apart: exclude the dataset in SOURCES.json, or "
                    "split it in a change to the gate")


def sniff(entry_id, data, syscalls):
    """(format, records, other) of the first native format that reads the whole file
    with at least one routed record, or (None, [reasons], 0)."""
    reasons = []
    for fmt in ("auditd-raw", "k8s-audit-json", "cloudtrail-json", "azure-monitor-json"):
        try:
            records, other = read_dataset({"id": entry_id, "format": fmt}, data, syscalls)
        except Fault as e:
            reasons.append(f"{fmt}: {e}")
            continue
        if any(r.logsource for r in records):
            return fmt, records, other
        reasons.append(f"{fmt}: no record routes to a log source of the repository")
    return None, reasons, 0
