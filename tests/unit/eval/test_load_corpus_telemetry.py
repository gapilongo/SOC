"""scripts/load_corpus_telemetry.py against a fake indexer: the documents, the time shift and the refusals.

The fake is a real HTTP server on the loopback interface that implements
``POST /<index>/_bulk`` the way OpenSearch does for ``index`` actions (a
document with a known ``_id`` is replaced). Nothing here talks to a real stack.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterator, List, Tuple

import pytest

from lg_sotf.eval.tool_fixtures import EventQuery, EventStore, event_time, field_values

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "load_corpus_telemetry.py"
INDEX = "wazuh-alerts-4.x-corpus-telemetry"
NOW = datetime(2026, 11, 14, 9, 0, tzinfo=UTC)
ED = "data.win.eventdata."
TYPO, PSEXEC, RANSOMWARE = "cv1-0003", "cv1-0069", "cv1-0113"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("load_corpus_telemetry", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


loader = _load_script()


class FakeIndexer:
    """What was indexed, by index and ``_id``, and every request the server saw."""

    def __init__(self, username: str, password: str):
        self.authorization = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.indices: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self.requests: List[Tuple[str, str]] = []
        self.reject: set[str] = set()

    def bulk(self, index: str, body: str) -> Dict[str, Any]:
        lines = [json.loads(line) for line in body.splitlines() if line.strip()]
        results = []
        for action, doc in zip(lines[::2], lines[1::2], strict=True):
            meta = action["index"]
            assert meta["_index"] == index
            if meta["_id"] in self.reject:
                results.append({"index": {"_id": meta["_id"], "status": 400, "error": {"type": "mapper_parsing_exception"}}})
                continue
            created = meta["_id"] not in self.indices.setdefault(index, {})
            self.indices[index][meta["_id"]] = doc
            results.append({"index": {"_id": meta["_id"], "status": 201 if created else 200}})
        return {"errors": any("error" in r["index"] for r in results), "items": results}

    def documents(self, index: str = INDEX) -> List[Dict[str, Any]]:
        return list(self.indices.get(index, {}).values())


@pytest.fixture
def indexer(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeIndexer]:
    fake = FakeIndexer("test-only-loader", "test-only-" + "x" * 12)  # built here, never a real credential

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            fake.requests.append((self.command, self.path))
            body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
            path = self.path.split("?", 1)[0]
            if self.headers.get("Authorization") != fake.authorization:
                status, answer = 401, {"error": "unauthorized"}
            elif not path.endswith("/_bulk") or path.count("/") != 2:
                status, answer = 405, {"error": "only POST /<index>/_bulk exists here"}
            else:
                status, answer = 200, fake.bulk(path.split("/")[1], body)
            payload = json.dumps(answer).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - the base class names it
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    username, password = base64.b64decode(fake.authorization.split(" ", 1)[1]).decode().split(":", 1)
    monkeypatch.setenv(loader.URL_ENV, f"http://127.0.0.1:{server.server_address[1]}")
    monkeypatch.setenv(loader.USERNAME_ENV, username)
    monkeypatch.setenv(loader.PASSWORD_ENV, password)
    monkeypatch.delenv(loader.CA_ENV, raising=False)
    try:
        yield fake
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _run(*args: str) -> int:
    return int(loader.main(["--now", "2026-11-14T09:00:00Z", *args]))


def test_the_context_of_the_chosen_items_is_indexed_around_now(
    indexer: FakeIndexer, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest_path = tmp_path / "out" / "manifest.json"
    code = _run("--host", "127.0.0.1", "--items", f"{TYPO},{PSEXEC}", "--pace", "60", "--manifest", str(manifest_path))
    out = capsys.readouterr()
    assert code == 0, out.err
    assert {path.split("?")[0] for _, path in indexer.requests} == {f"/{INDEX}/_bulk"}  # nothing else is called
    alerts, store = loader.load_dataset("corpus_v1")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["dataset"] == "corpus_v1" and manifest["index"] == INDEX
    assert [(row["item"], row["anchor"]) for row in manifest["items"]] == [
        (TYPO, "2026-11-14T09:00:00.000+0000"), (PSEXEC, "2026-11-14T09:01:00.000+0000")]
    indexed = indexer.indices[INDEX]
    assert len(indexed) == sum(row["documents"] for row in manifest["items"])
    assert f"{len(indexed)} documents around 2 items of corpus_v1 indexed into {INDEX}" in out.out
    for position, item_id in enumerate((TYPO, PSEXEC)):
        anchor = NOW + timedelta(seconds=60 * position)
        delta = anchor - event_time(alerts[item_id])
        originals = {str(d["id"]): d for d in loader.context_docs(store, alerts[item_id])}
        copies = {key.split(":", 1)[1]: doc for key, doc in indexed.items() if key.startswith(item_id + ":")}
        assert set(copies) == set(originals) and str(alerts[item_id]["id"]) in copies  # the alert itself is there too
        for doc_id, original in originals.items():
            copy = copies[doc_id]
            moved = event_time(original) + delta
            assert event_time(copy) == moved  # every document keeps its distance from the alert
            assert copy["@timestamp"] == copy["timestamp"].replace("+0000", "Z")
            assert copy["id"] == f"{int(moved.timestamp())}.{doc_id.split('.', 1)[1]}"
            assert copy["data"]["win"]["system"]["systemTime"].startswith(moved.strftime("%Y-%m-%dT%H:%M:%S"))
            unchanged = {k: v for k, v in copy.items() if k not in ("timestamp", "@timestamp", "id", "data")}
            assert unchanged == {k: v for k, v in original.items() if k not in ("timestamp", "@timestamp", "id", "data")}
            assert copy["data"]["win"]["eventdata"].keys() == original["data"]["win"]["eventdata"].keys()
        assert event_time(copies[str(alerts[item_id]["id"])]) == anchor
    # A fresh store over what was indexed answers the questions the evidence tools ask, at the new time.
    live = EventStore(indexer.documents()).as_of(NOW + timedelta(minutes=30))
    typo_ip = field_values(alerts[TYPO], ED + "ipAddress")
    assert live.count(EventQuery(start=NOW, end=NOW + timedelta(minutes=10), event_ids=("4624",),
                                 where={ED + "ipAddress": typo_ip})) == 1  # the success after the typo
    psexec_at = NOW + timedelta(seconds=60)
    inbound = live.select(EventQuery(agent=alerts[PSEXEC]["agent"]["name"], start=psexec_at - timedelta(minutes=15),
                                     end=psexec_at, event_ids=("4624",), where={ED + "logonType": "3"}))
    assert [field_values(d, ED + "workstationName") for d in inbound] == [["IT-WS-01"]]
    # The estate's history comes along for prevalence: PsExec was installed on other hosts in the weeks before.
    history = live.distinct(EventQuery(end=psexec_at - timedelta(days=1), event_ids=("7045",),
                                       where={ED + "serviceName": "PSEXESVC"}), "agent.name")
    assert len(history) >= 5


def test_loading_twice_replaces_the_documents_and_moves_them_to_the_new_now(
    indexer: FakeIndexer, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run("--host", "127.0.0.1", "--items", RANSOMWARE) == 0
    first = dict(indexer.indices[INDEX])
    assert _run("--host", "127.0.0.1", "--items", RANSOMWARE) == 0
    assert indexer.indices[INDEX] == first  # same anchor: identical documents, none added
    assert loader.main(["--now", "2026-11-15T09:00:00+00:00", "--host", "127.0.0.1", "--items", RANSOMWARE]) == 0
    assert indexer.indices[INDEX].keys() == first.keys()  # a new anchor: the same ids, one day later
    for key, doc in indexer.indices[INDEX].items():
        assert event_time(doc) - event_time(first[key]) == timedelta(days=1)
    capsys.readouterr()


def test_a_host_that_was_not_passed_is_refused_and_nothing_is_printed_about_it(
    indexer: FakeIndexer, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_url = str(loader.os.environ[loader.URL_ENV])
    password = str(loader.os.environ[loader.PASSWORD_ENV])
    port = secret_url.rsplit(":", 1)[1]
    for hosts in ([], ["--host", "indexer.example.test"], ["--host", "localhost"]):
        assert _run(*hosts, "--items", TYPO) == 2
        captured = capsys.readouterr()
        assert "was not passed with --host" in captured.err
        assert secret_url not in captured.err + captured.out and port not in captured.err + captured.out
    assert indexer.requests == []  # refused before any request
    # A wrong password: the server says no, the output names neither the URL nor a credential.
    monkeypatch.setenv(loader.PASSWORD_ENV, "test-only-" + "y" * 12)
    assert _run("--host", "127.0.0.1", "--items", TYPO) == 2
    captured = capsys.readouterr()
    assert "HTTP 401" in captured.err and indexer.documents() == []
    for text in (secret_url, port, password, "test-only-"):
        assert text not in captured.err + captured.out
    # Missing settings are named by their variable, never by value.
    monkeypatch.delenv(loader.PASSWORD_ENV)
    assert _run("--host", "127.0.0.1", "--items", TYPO) == 2
    assert loader.PASSWORD_ENV in capsys.readouterr().err
    monkeypatch.delenv(loader.URL_ENV)
    assert _run("--host", "127.0.0.1", "--items", TYPO) == 2
    assert loader.URL_ENV in capsys.readouterr().err


def test_an_unreachable_indexer_and_rejected_documents_are_reported_without_the_url(
    indexer: FakeIndexer, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    alerts, _ = loader.load_dataset("corpus_v1")
    indexer.reject.add(f"{TYPO}:{alerts[TYPO]['id']}")
    assert _run("--host", "127.0.0.1", "--items", TYPO) == 2
    assert "1 rejected: mapper_parsing_exception" in capsys.readouterr().err
    monkeypatch.setenv(loader.URL_ENV, "http://127.0.0.1:1")  # nothing listens there
    assert _run("--host", "127.0.0.1", "--items", TYPO) == 2
    err = capsys.readouterr().err
    assert "the indexer request failed" in err and "127.0.0.1" not in err
    for bad in ("ftp://127.0.0.1/x", "http://user:pw@127.0.0.1:9200", "not a url"):
        monkeypatch.setenv(loader.URL_ENV, bad)
        assert _run("--host", "127.0.0.1", "--items", TYPO) == 2
        assert bad not in capsys.readouterr().err


def test_a_dry_run_reads_no_environment_and_sends_nothing(
    indexer: FakeIndexer, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in (loader.URL_ENV, loader.USERNAME_ENV, loader.PASSWORD_ENV):
        monkeypatch.delenv(name)
    listing = tmp_path / "items.txt"
    listing.write_text("# the skills dataset\ncsk1-0001\ncsk1-0002 a comment\n\n", encoding="utf-8")
    assert _run("--dry-run", "--dataset", "corpus_skills_v1", "--items-file", str(listing), "--items", "csk1-0001") == 0
    assert "dry run:" in capsys.readouterr().out and indexer.requests == []
    for args, message in (
        (["--dry-run", "--items", "cv1-9999"], "not items of corpus_v1: cv1-9999"),
        (["--dry-run"], "no items"),
        (["--dry-run", "--items", TYPO, "--index", "wazuh-alerts-*"], "one concrete index name"),
    ):
        assert _run(*args) == 2
        assert message in capsys.readouterr().err
    assert loader.main(["--dry-run", "--items", TYPO, "--now", "yesterday"]) == 2
    assert loader.main(["--dry-run", "--items", TYPO, "--now", "2026-11-14T09:00:00"]) == 2
    assert "time zone" in capsys.readouterr().err
    assert loader.main(["--dry-run", "--items", TYPO]) == 0  # no --now: the current time
    capsys.readouterr()


def test_the_context_of_an_alert_is_what_the_evidence_tools_can_read() -> None:
    alerts, store = loader.load_dataset("corpus_v1")
    with pytest.raises(loader.LoadError, match="unknown dataset"):
        loader.load_dataset("corpus_v2")
    for item_id in (TYPO, PSEXEC, RANSOMWARE, "cv1-0057", "cv1-0021", "cv1-0025", "cv1-0001"):
        alert = alerts[item_id]
        at, host = event_time(alert), alert["agent"]["name"]
        docs = loader.context_docs(store, alert)
        ids = [d["id"] for d in docs]
        assert alert["id"] in ids and len(set(ids)) == len(ids)
        assert [event_time(d) for d in docs] == sorted(event_time(d) for d in docs)
        assert all(event_time(d) <= at + timedelta(minutes=60) for d in docs)  # nothing from later than the tools see
        near = store.as_of(at + timedelta(minutes=60)).select(EventQuery(agent=host, start=at - timedelta(minutes=60)))
        assert {d["id"] for d in near} <= set(ids)  # the host's hour either side
    spray = loader.context_docs(store, alerts["cv1-0021"])
    users = {v for d in spray for v in field_values(d, ED + "targetUserName") if field_values(d, "rule.id") != ["60106"]}
    assert len(users) >= 4  # the other accounts the source tried
    lockout = loader.context_docs(store, alerts["cv1-0025"])  # a 4740 names the calling computer, not an address
    assert sum(field_values(d, ED + "workstationName") == ["SALES-WS-03"] for d in lockout) >= 4
    updater = loader.context_docs(store, alerts["cv1-0057"])
    assert len({d["agent"]["name"] for d in updater if field_values(d, ED + "serviceName") == ["edgeupdate"]}) >= 10
