"""Helm chart deploy/helm/lg-sotf rendered with default and full values (skipped without helm)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml
from pydantic import BaseModel

from lg_sotf.settings import Settings
from tests.deploy._support import (
    CHART_DIR,
    FULL_VALUES,
    Manifest,
    find,
    one,
    render,
    requires_helm,
    run_helm_template,
)

pytestmark = requires_helm

WORKLOADS = ("api", "worker", "scheduler")


def pod_spec(m: Manifest) -> Dict[str, Any]:
    return m["spec"]["template"]["spec"]


def container(m: Manifest) -> Dict[str, Any]:
    containers = pod_spec(m)["containers"]
    assert len(containers) == 1
    return containers[0]


def env_from_secrets(m: Manifest) -> List[str]:
    return [e["secretRef"]["name"] for e in container(m).get("envFrom", []) if "secretRef" in e]


def lg_sotf_pods(manifests: List[Manifest]) -> List[Manifest]:
    return [m for m in manifests if m["kind"] in ("Deployment", "Job") and not m["metadata"]["name"].endswith("-frontend")]


# ---------------------------------------------------------------------------
# Security posture
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("values", ["default", "full"])
def test_pods_are_hardened(values: str, request: pytest.FixtureRequest) -> None:
    manifests: List[Manifest] = request.getfixturevalue(f"{values}_manifests")
    pods = [m for m in manifests if m["kind"] in ("Deployment", "Job")]
    assert pods
    for m in pods:
        spec = pod_spec(m)
        name = m["metadata"]["name"]
        assert spec["automountServiceAccountToken"] is False, name
        psc = spec["securityContext"]
        assert psc["runAsNonRoot"] is True and psc["runAsUser"] == 10001, name
        assert psc["seccompProfile"] == {"type": "RuntimeDefault"}, name
        c = container(m)
        csc = c["securityContext"]
        assert csc["readOnlyRootFilesystem"] is True, name
        assert csc["allowPrivilegeEscalation"] is False, name
        assert csc["capabilities"] == {"drop": ["ALL"]}, name
        assert c["resources"]["requests"] and c["resources"]["limits"], name
        mounts = {vm["mountPath"]: vm["name"] for vm in c["volumeMounts"]}
        assert "/tmp" in mounts, name
        tmp = next(v for v in spec["volumes"] if v["name"] == mounts["/tmp"])
        assert "emptyDir" in tmp and tmp["emptyDir"]["sizeLimit"], name


def test_service_accounts_do_not_automount(default_manifests: List[Manifest]) -> None:
    accounts = find(default_manifests, "ServiceAccount")
    assert accounts
    assert all(sa["automountServiceAccountToken"] is False for sa in accounts)


@pytest.mark.parametrize("values", ["default", "full"])
def test_chart_never_renders_secrets(values: str, request: pytest.FixtureRequest) -> None:
    manifests: List[Manifest] = request.getfixturevalue(f"{values}_manifests")
    assert not find(manifests, "Secret")
    for cm in find(manifests, "ConfigMap"):
        text = yaml.safe_dump(cm["data"]).lower()
        for word in ("jwt_secret", "encryption_keys", "indicator_hmac_key", "api_key", "password", "metrics_token"):
            assert word not in text, f"{cm['metadata']['name']} contains {word}"


@pytest.mark.parametrize(
    "setting",
    [
        "settings.auth.jwt_secret=x",
        "settings.database.url=postgresql://u:p@h/db",
        "settings.database.migration_url=postgresql://u:p@h/db",
        "settings.database.shadow_url=postgresql://u:p@h/db",
        "settings.redis.url=redis://:p@h:6379/0",
        "settings.llm.api_key=x",
        "settings.security.encryption_keys=x",
        "settings.api.metrics_token=x",
        "settings.response.webhook_secret=x",
        "settings.auth.bootstrap_admin_password=x",
    ],
)
def test_schema_rejects_secret_values(setting: str) -> None:
    proc = run_helm_template("--set", setting, check=False)
    assert proc.returncode != 0
    assert "values don't meet the specifications of the schema" in proc.stderr or "schema" in proc.stderr


@pytest.mark.parametrize(
    "override",
    [
        "podSecurityContext.runAsNonRoot=false",
        "containerSecurityContext.allowPrivilegeEscalation=true",
        "apiTypo.enabled=true",
        "settings.llm.provider=openia",
        "settings.api.cors_origins={*}",
    ],
)
def test_schema_rejects_unsafe_or_mistyped_values(override: str) -> None:
    assert run_helm_template("--set", override, check=False).returncode != 0


# ---------------------------------------------------------------------------
# Workloads
# ---------------------------------------------------------------------------


def test_default_render_has_expected_resources(default_manifests: List[Manifest]) -> None:
    kinds = sorted((m["kind"], m["metadata"]["name"]) for m in default_manifests)
    names = {name for _, name in kinds}
    for component in WORKLOADS:
        assert f"t-lg-sotf-{component}" in names
    assert ("Job", "t-lg-sotf-migrate") in kinds
    assert ("HorizontalPodAutoscaler", "t-lg-sotf-api") in kinds
    assert not find(default_manifests, "ScaledObject")
    assert not find(default_manifests, "Ingress")
    assert not find(default_manifests, "NetworkPolicy")
    assert not find(default_manifests, "ServiceMonitor")
    # The web UI ships enabled by default, with its own Service and PodDisruptionBudget.
    assert one(default_manifests, "Deployment", "-frontend")
    assert one(default_manifests, "Service", "-frontend")
    pdbs = {m["metadata"]["name"] for m in find(default_manifests, "PodDisruptionBudget")}
    assert pdbs == {f"t-lg-sotf-{c}" for c in WORKLOADS} | {"t-lg-sotf-frontend"}


def test_api_probes_and_args(default_manifests: List[Manifest]) -> None:
    api = one(default_manifests, "Deployment", "-api")
    c = container(api)
    assert c["args"][0] == "api"
    assert c["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert c["readinessProbe"]["httpGet"]["path"] == "/readyz"
    assert c["startupProbe"]["httpGet"]["path"] == "/healthz"
    assert c["ports"] == [{"name": "http", "containerPort": 8000, "protocol": "TCP"}]
    assert "replicas" not in api["spec"], "the HPA owns the replica count"
    assert c["lifecycle"]["preStop"]["exec"]["command"] == ["sleep", "5"]
    assert api["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] == 0


@pytest.mark.parametrize("component", ["worker", "scheduler"])
def test_worker_and_scheduler_probe_the_health_port(default_manifests: List[Manifest], component: str) -> None:
    dep = one(default_manifests, "Deployment", f"-{component}")
    c = container(dep)
    assert c["args"] == [component, "--metrics-port", "9100"]
    assert c["ports"] == [{"name": "health", "containerPort": 9100, "protocol": "TCP"}]
    for probe, path in (("livenessProbe", "/healthz"), ("readinessProbe", "/readyz"), ("startupProbe", "/healthz")):
        assert c[probe]["httpGet"] == {"path": path, "port": "health"}, probe


def test_scheduler_runs_two_replicas_for_leader_election(default_manifests: List[Manifest]) -> None:
    sched = one(default_manifests, "Deployment", "-scheduler")
    assert sched["spec"]["replicas"] == 2
    pdb = one(default_manifests, "PodDisruptionBudget", "-scheduler")
    assert pdb["spec"]["maxUnavailable"] == 1


def test_worker_grace_period_exceeds_drain_timeout(default_manifests: List[Manifest]) -> None:
    worker = one(default_manifests, "Deployment", "-worker")
    cm = one(default_manifests, "ConfigMap", "-config")
    drain = yaml.safe_load(cm["data"]["settings.yaml"])["worker"]["drain_timeout_s"]
    assert pod_spec(worker)["terminationGracePeriodSeconds"] > drain


def test_topology_spread_defaults(default_manifests: List[Manifest]) -> None:
    for component in WORKLOADS:
        spec = pod_spec(one(default_manifests, "Deployment", f"-{component}"))
        keys = [t["topologyKey"] for t in spec["topologySpreadConstraints"]]
        assert keys == ["topology.kubernetes.io/zone", "kubernetes.io/hostname"], component
        for t in spec["topologySpreadConstraints"]:
            assert t["labelSelector"]["matchLabels"]["app.kubernetes.io/component"] == component


def test_config_changes_roll_pods(default_manifests: List[Manifest]) -> None:
    for component in WORKLOADS:
        ann = one(default_manifests, "Deployment", f"-{component}")["spec"]["template"]["metadata"]["annotations"]
        assert len(ann["checksum/config"]) == 64


# ---------------------------------------------------------------------------
# Migrations and secrets wiring
# ---------------------------------------------------------------------------


def test_migrate_is_a_pre_install_and_pre_upgrade_hook(default_manifests: List[Manifest]) -> None:
    job = one(default_manifests, "Job", "-migrate")
    ann = job["metadata"]["annotations"]
    assert ann["helm.sh/hook"] == "pre-install,pre-upgrade"
    assert ann["helm.sh/hook-delete-policy"] == "before-hook-creation"
    assert container(job)["args"] == ["migrate"]
    assert pod_spec(job)["restartPolicy"] == "Never"
    assert job["spec"]["backoffLimit"] >= 1 and job["spec"]["activeDeadlineSeconds"] > 0
    # Hook resources exist before the release's own ConfigMap/ServiceAccount do.
    hook_cm = one(default_manifests, "ConfigMap", "-config-migrate")
    assert hook_cm["metadata"]["annotations"]["helm.sh/hook"] == "pre-install,pre-upgrade"
    assert int(hook_cm["metadata"]["annotations"]["helm.sh/hook-weight"]) < int(ann["helm.sh/hook-weight"])
    assert hook_cm["data"] == one(default_manifests, "ConfigMap", "-config")["data"]
    config_volume = next(v for v in pod_spec(job)["volumes"] if v["name"] == "config")
    assert config_volume["configMap"]["name"] == hook_cm["metadata"]["name"]
    hook_sa = one(default_manifests, "ServiceAccount", "-migrate")
    assert pod_spec(job)["serviceAccountName"] == hook_sa["metadata"]["name"]


def _plain_migrate_job(*args: str) -> Manifest:
    manifests = render("--set", "migrate.useHelmHooks=false", *args)
    jobs = find(manifests, "Job")
    assert len(jobs) == 1
    assert not find(manifests, "ConfigMap", "-config-migrate")
    return jobs[0]


def test_migrate_without_hooks_is_an_ordinary_job() -> None:
    job = _plain_migrate_job()
    ann = job["metadata"].get("annotations") or {}
    assert not any(k.startswith("helm.sh/hook") for k in ann)
    assert ann["argocd.argoproj.io/sync-wave"] == "-1", "GitOps tools must sync it before the Deployments"
    assert re.fullmatch(r"t-lg-sotf-migrate-[0-9a-f]{8}", job["metadata"]["name"])


def test_migrate_job_name_changes_with_image_and_settings_but_is_stable_otherwise() -> None:
    """A Job's pod template is immutable: an upgrade must create a new Job, not patch the old one."""
    base = _plain_migrate_job("--set", "image.tag=1.0.1")["metadata"]["name"]
    assert _plain_migrate_job("--set", "image.tag=1.0.1")["metadata"]["name"] == base
    assert _plain_migrate_job("--set", "image.tag=1.0.2")["metadata"]["name"] != base
    assert _plain_migrate_job("--set", "image.tag=1.0.1", "--set", "settings.worker.concurrency=4")[
        "metadata"
    ]["name"] != base
    # Unrelated values (replica counts) do not churn the Job.
    assert _plain_migrate_job("--set", "image.tag=1.0.1", "--set", "api.replicaCount=5")["metadata"]["name"] == base


def test_owner_and_bootstrap_secrets_reach_only_the_components_that_need_them(
    full_manifests: List[Manifest],
) -> None:
    runtime, owner, bootstrap = "lg-sotf-runtime", "lg-sotf-owner", "lg-sotf-bootstrap"
    assert env_from_secrets(one(full_manifests, "Deployment", "-api")) == [runtime]
    # The shadow-run login (AI-E1.5c) reaches the worker only.
    assert env_from_secrets(one(full_manifests, "Deployment", "-worker")) == [runtime, "lg-sotf-shadow"]
    assert env_from_secrets(one(full_manifests, "Deployment", "-scheduler")) == [runtime, owner]
    assert env_from_secrets(one(full_manifests, "Job", "-migrate")) == [runtime, owner, bootstrap]


def test_default_runtime_secret_name_is_the_release_fullname(default_manifests: List[Manifest]) -> None:
    for m in lg_sotf_pods(default_manifests):
        assert env_from_secrets(m) == ["t-lg-sotf"], m["metadata"]["name"]


def test_every_process_loads_the_settings_file(full_manifests: List[Manifest]) -> None:
    for m in lg_sotf_pods(full_manifests):
        env = {e["name"]: e.get("value") for e in container(m)["env"]}
        assert env["LG_SOTF_CONFIG_FILE"] == "/etc/lg-sotf/settings.yaml"
        assert env["HTTPS_PROXY"] == "http://proxy.internal:3128"  # extraEnv reaches every process


def test_image_digest_takes_precedence(full_manifests: List[Manifest]) -> None:
    image = container(one(full_manifests, "Deployment", "-api"))["image"]
    assert image == "registry.example.com/lg-sotf@sha256:" + "0" * 64


def _unknown_keys(model: type, data: Dict[str, Any], prefix: str = "") -> List[str]:
    unknown: List[str] = []
    fields = model.model_fields  # type: ignore[attr-defined]
    for key, value in data.items():
        if key not in fields:
            unknown.append(prefix + key)
            continue
        annotation = fields[key].annotation
        if isinstance(value, dict) and isinstance(annotation, type) and issubclass(annotation, BaseModel):
            unknown.extend(_unknown_keys(annotation, value, f"{prefix}{key}."))
    return unknown


@pytest.mark.parametrize("values", ["default", "full"])
def test_settings_configmap_matches_the_settings_model(
    values: str, request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifests: List[Manifest] = request.getfixturevalue(f"{values}_manifests")
    text = one(manifests, "ConfigMap", "-config")["data"]["settings.yaml"]
    data = yaml.safe_load(text)
    assert _unknown_keys(Settings, data) == [], "chart settings keys must exist in lg_sotf.settings"
    path = tmp_path / "settings.yaml"
    path.write_text(text)
    for var in ("LG_SOTF_ENVIRONMENT", "LG_SOTF_ENV", "LG_SOTF_CONFIG_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    settings = Settings(config_file=str(path))
    assert settings.environment == "production"
    assert settings.api.host == "0.0.0.0"  # noqa: S104 - pods listen on the pod IP
    assert settings.auth.cookie_secure is True
    assert settings.response.dry_run is True
    assert settings.llm.provider == "anthropic"


# ---------------------------------------------------------------------------
# Optional features (full values)
# ---------------------------------------------------------------------------


def test_keda_scales_workers_on_both_streams(full_manifests: List[Manifest]) -> None:
    so = one(full_manifests, "ScaledObject", "-worker")
    assert so["spec"]["scaleTargetRef"]["name"] == "t-lg-sotf-worker"
    triggers = so["spec"]["triggers"]
    assert [t["type"] for t in triggers] == ["redis-streams", "redis-streams"]
    assert [t["metadata"]["stream"] for t in triggers] == ["lgsotf:q:alerts:high", "lgsotf:q:alerts:normal"]
    for t in triggers:
        md = t["metadata"]
        assert md["consumerGroup"] == "workers"
        assert md["lagCount"] == "16"
        assert md["enableTLS"] == "true"
        assert t["authenticationRef"]["name"] == "t-lg-sotf-worker-redis"
    assert so["spec"]["fallback"] == {"failureThreshold": 3, "replicas": 4}
    auth = one(full_manifests, "TriggerAuthentication", "-worker-redis")
    assert auth["spec"]["secretTargetRef"] == [{"parameter": "password", "name": "redis-auth", "key": "password"}]
    assert not find(full_manifests, "HorizontalPodAutoscaler", "-worker"), "KEDA owns the worker HPA"
    assert "replicas" not in one(full_manifests, "Deployment", "-worker")["spec"]


def test_worker_cpu_hpa_is_the_fallback_without_keda() -> None:
    manifests = render("--set", "worker.autoscaling.enabled=true")
    hpa = one(manifests, "HorizontalPodAutoscaler", "-worker")
    assert hpa["spec"]["scaleTargetRef"]["name"] == "t-lg-sotf-worker"
    assert not find(manifests, "ScaledObject")


def test_stream_names_follow_the_redis_key_prefix() -> None:
    manifests = render("--set", "worker.keda.enabled=true", "--set", "settings.redis.key_prefix=acme")
    streams = [t["metadata"]["stream"] for t in one(manifests, "ScaledObject", "-worker")["spec"]["triggers"]]
    assert streams == ["acme:q:alerts:high", "acme:q:alerts:normal"]


def test_ingress_tls_and_routing(full_manifests: List[Manifest]) -> None:
    ing = one(full_manifests, "Ingress", "t-lg-sotf")
    assert ing["spec"]["ingressClassName"] == "nginx"
    assert ing["spec"]["tls"] == [{"secretName": "lg-sotf-tls", "hosts": ["soc.example.com"]}]
    paths = {p["path"]: p["backend"]["service"]["name"] for p in ing["spec"]["rules"][0]["http"]["paths"]}
    assert paths == {"/api": "t-lg-sotf-api", "/": "t-lg-sotf-frontend"}


def test_service_monitors_scrape_every_role(full_manifests: List[Manifest]) -> None:
    monitors = {m["metadata"]["name"]: m for m in find(full_manifests, "ServiceMonitor")}
    assert set(monitors) == {f"t-lg-sotf-{c}" for c in WORKLOADS}
    api_ep = monitors["t-lg-sotf-api"]["spec"]["endpoints"][0]
    assert api_ep["port"] == "http"
    assert api_ep["authorization"]["credentials"] == {"name": "lg-sotf-runtime", "key": "LG_SOTF_API__METRICS_TOKEN"}
    for c in ("worker", "scheduler"):
        ep = monitors[f"t-lg-sotf-{c}"]["spec"]["endpoints"][0]
        assert ep["port"] == "health" and ep["path"] == "/metrics"
        assert "authorization" not in ep


def test_network_policies(full_manifests: List[Manifest]) -> None:
    policies = {m["metadata"]["name"]: m for m in find(full_manifests, "NetworkPolicy")}
    assert set(policies) == {
        "t-lg-sotf-api", "t-lg-sotf-frontend", "t-lg-sotf-worker", "t-lg-sotf-scheduler",
        "t-lg-sotf-migrate", "t-lg-sotf-egress",
    }
    api_rules = policies["t-lg-sotf-api"]["spec"]["ingress"]
    assert all(rule["ports"] == [{"port": "http", "protocol": "TCP"}] for rule in api_rules)
    for rule in api_rules:
        assert rule.get("from"), "no API ingress rule may admit every source"
    sources = [rule["from"] for rule in api_rules]
    assert sources[0] == [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-nginx"}}}]
    # The ServiceMonitor scrape of the API /metrics comes from networkPolicy.metricsFrom ...
    assert [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "monitoring"}}}] in sources
    # ... and the chart's own `helm test` pod reaches /readyz.
    test_pod = one(full_manifests, "Pod", "-test-api-readyz")
    test_rule = next(src for src in sources if "podSelector" in src[0])
    selector = test_rule[0]["podSelector"]["matchLabels"]
    assert selector.items() <= test_pod["metadata"]["labels"].items()
    assert selector["app.kubernetes.io/instance"] == "t"
    worker = policies["t-lg-sotf-worker"]["spec"]["ingress"][0]
    assert worker["ports"] == [{"port": "health", "protocol": "TCP"}]
    assert policies["t-lg-sotf-migrate"]["spec"].get("ingress") is None
    egress = policies["t-lg-sotf-egress"]["spec"]["egress"]
    ports = [p["port"] for rule in egress for p in rule["ports"]]
    assert {53, 5432, 6379, 443, 8000} <= set(ports)


def test_api_network_policy_admits_scrape_and_test_pod_only_when_enabled() -> None:
    manifests = render(
        "-f", str(FULL_VALUES), "--set", "serviceMonitor.enabled=false", "--set", "tests.enabled=false"
    )
    api_rules = one(manifests, "NetworkPolicy", "-api")["spec"]["ingress"]
    assert len(api_rules) == 1, "only networkPolicy.api.from"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (["--set", "networkPolicy.enabled=true"], "networkPolicy.api.from must list"),
        (
            ["--set", "networkPolicy.enabled=true", "--set", "serviceMonitor.enabled=true",
             "--set", "networkPolicy.api.from[0].podSelector.matchLabels.app=ingress"],
            "networkPolicy.metricsFrom must select",
        ),
    ],
)
def test_network_policy_refuses_open_api_sources(overrides: List[str], message: str) -> None:
    proc = run_helm_template(*overrides, check=False)
    assert proc.returncode != 0
    assert message in proc.stderr


def test_forwarded_allow_ips_trusts_no_proxy_by_default(default_manifests: List[Manifest]) -> None:
    settings = yaml.safe_load(one(default_manifests, "ConfigMap", "-config")["data"]["settings.yaml"])
    assert settings["api"]["forwarded_allow_ips"] == "127.0.0.1"
    values = yaml.safe_load((CHART_DIR / "values.yaml").read_text())
    assert values["settings"]["api"]["forwarded_allow_ips"] == "127.0.0.1"


def test_frontend_is_rendered_only_when_enabled(full_manifests: List[Manifest]) -> None:
    dep = one(full_manifests, "Deployment", "-frontend")
    c = container(dep)
    assert c["image"].startswith("ghcr.io/gapilongo/lg-sotf-frontend:")
    assert "envFrom" not in c, "the static UI gets no secrets"


def test_chart_files_exist() -> None:
    for name in ("Chart.yaml", "values.yaml", "values.schema.json", "templates/NOTES.txt"):
        assert (CHART_DIR / name).is_file(), name


@requires_helm
@pytest.mark.parametrize(
    "key",
    [
        "settings.tools.virustotal.api_key",
        "settings.tools.abuseipdb.apikey",
        "settings.tools.misp.token",
        "settings.tools.shodan.client_secret",
        "settings.tools.api_key",
    ],
)
def test_schema_rejects_enrichment_secrets_under_settings(key: str) -> None:
    """WSC-5: provider keys would land in the plaintext ConfigMap."""
    proc = run_helm_template("--set", f"{key}=SECRETVALUE", check=False)
    assert proc.returncode != 0
    assert "SECRETVALUE" not in proc.stdout


@requires_helm
def test_schema_keeps_non_secret_tool_settings() -> None:
    proc = run_helm_template(
        "--set", "settings.tools.virustotal.timeout=15", "--set", "settings.tools.internal_domains={corp.example}"
    )
    assert "timeout: 15" in proc.stdout
