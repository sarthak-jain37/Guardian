"""Bounded, tenant-scoped telemetry from trusted local Hubble/Tetragon exporters."""
import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from backend.app.services.runtime_evidence import audit_details, runtime_details

log = logging.getLogger(__name__)


def normalize(raw, source, cluster):
    event = {"cluster": cluster, "source": source, "observed_at": datetime.now(timezone.utc).isoformat()}
    if source == "audit":
        details = audit_details(raw)
        if not details:
            return None
        event.update(details)
    elif source == "hubble":
        flow = raw.get("flow") or (raw if "verdict" in raw or "IP" in raw else None)
        if not flow:
            return None
        def endpoint(side):
            ep = flow.get(side) or {}
            return {"namespace": ep.get("namespace", ""), "pod": ep.get("pod_name", ""),
                    "ip": (flow.get("IP") or {}).get("source" if side == "source" else "destination", "")}
        l7 = flow.get("l7") or {}
        http = l7.get("http") or {}
        event.update(kind="network", timestamp=flow.get("time"), source_pod=endpoint("source"),
                     destination_pod=endpoint("destination"), verdict=flow.get("verdict"),
                     drop_reason=flow.get("drop_reason_desc"), l4=flow.get("l4", {}),
                     traffic_direction=flow.get("traffic_direction"), l7_type=l7.get("type"))
        if http:
            # Never store credentials, query parameters, bodies or HTTP headers.
            url = urlsplit(http.get("url", ""))
            event["http"] = {"method": http.get("method"), "host": url.hostname,
                             "path": url.path, "code": http.get("code"),
                             "protocol": http.get("protocol"), "latency_ns": l7.get("latency_ns")}
        if l7.get("dns"):
            dns = l7["dns"]
            event["dns"] = {k: dns[k] for k in ("query", "ips", "rcode", "qtypes") if k in dns}
    else:
        kind = next((k for k in ("process_exec", "process_exit", "process_kprobe", "process_tracepoint", "process_uprobe", "process_lsm") if k in raw), None)
        if not kind:
            return None
        payload = raw[kind]
        process = payload.get("process") or {}
        pod = process.get("pod") or {}
        event.update(kind=kind, timestamp=raw.get("time"),
                     source_pod={"namespace": pod.get("namespace", ""), "pod": pod.get("name", "")},
                     process={k: process[k] for k in ("binary", "uid", "pid", "exec_id") if k in process},
                     parent_binary=(payload.get("parent") or {}).get("binary"),
                     policy_name=payload.get("policy_name"), function_name=payload.get("function_name"),
                     signal=payload.get("signal"), status=payload.get("status"))
        event["source_pod"]["uid"] = pod.get("uid")
        event["runtime"], event["signals"] = runtime_details(payload)
    # Stable source identity permits replay without duplicate storage.
    event["id"] = hashlib.sha256((cluster + source + json.dumps(raw, sort_keys=True)).encode()).hexdigest()
    return event


class Telemetry:
    def __init__(self, redis):
        self.redis = redis
        self.cluster = os.getenv("GUARDIAN_CLUSTER_ID", "local")
        self.prefix = f"guardian:telemetry:{self.cluster}"
        self.maximum = max(100, int(os.getenv("TELEMETRY_MAX_EVENTS", "50000")))
        self.ttl = max(60, int(os.getenv("TELEMETRY_RETENTION_SECONDS", "604800")))
        self.health = {}
        policy_path = os.getenv("TELEMETRY_BOUNDARIES_FILE")
        self.boundaries = json.loads(Path(policy_path).read_text()) if policy_path else []

    def findings(self, event):
        findings = list(event.get("signals", []))
        if event.get("verdict") in ("DROPPED", "ERROR", "AUDIT"):
            findings.append("network_policy_or_delivery_failure")
        if event.get("process", {}).get("uid") == 0:
            findings.append("root_process_observed")
        pod = event.get("source_pod", {})
        for rule in self.boundaries:
            if rule.get("namespace") != pod.get("namespace") or rule.get("pod", pod.get("pod")) != pod.get("pod"):
                continue
            if event["kind"] == "network":
                dst = event["destination_pod"]
                if "allowed_destination_namespaces" in rule and dst.get("namespace") and dst["namespace"] not in rule["allowed_destination_namespaces"]:
                    findings.append("destination_namespace_outside_boundary")
                if rule.get("allow_external") is False and not dst.get("pod") and dst.get("ip"):
                    findings.append("unresolved_or_external_destination")
            binary = event.get("process", {}).get("binary")
            if binary and "allowed_binaries" in rule and binary not in rule["allowed_binaries"]:
                findings.append("binary_outside_boundary")
        return sorted(set(findings))

    async def archive(self, event):
        """Retain pod histories independently of the noisy global event list."""
        namespaces={e.get('namespace') for e in (event.get('source_pod',{}),event.get('destination_pod',{}),event.get('target',{})) if e.get('namespace')}
        keys=[self.prefix+':history:namespace:'+ns for ns in sorted(namespaces)]
        # A per-pod index also protects quiet pods sharing a busy namespace.
        for endpoint in (event.get('source_pod',{}),event.get('destination_pod',{})):
            if endpoint.get('namespace') and endpoint.get('pod'):
                keys.append(self.prefix+':history:pod:'+endpoint['namespace']+'/'+endpoint['pod'])
        target=event.get('target',{})
        if target.get('resource')=='pods' and target.get('namespace') and target.get('name'):
            keys.append(self.prefix+':history:pod:'+target['namespace']+'/'+target['name'])
        keys=sorted(set(keys))
        if not keys:return
        script="""
        if redis.call('EXISTS',KEYS[1]) == 1 then return 0 end
        redis.call('SET',KEYS[1],'1','EX',ARGV[3])
        for i=2,#KEYS do
          redis.call('LPUSH',KEYS[i],ARGV[1])
          redis.call('LTRIM',KEYS[i],0,tonumber(ARGV[2])-1)
          redis.call('EXPIRE',KEYS[i],ARGV[3])
        end
        return 1
        """
        await self.redis.eval(script,len(keys)+1,self.prefix+':history:seen:'+event['id'],*keys,
                              json.dumps(event),self.maximum,self.ttl)

    async def pod_history(self, namespace, name):
        values=await self.redis.lrange(self.prefix+':history:pod:'+namespace+'/'+name,0,self.maximum-1)
        return await asyncio.to_thread(self._filter_events,values,self.maximum,namespace,None)

    async def save(self, event):
        event["findings"] = self.findings(event)
        await self.archive(event)
        # Atomic deduplication and bounded retention, including concurrent collectors.
        script = """
        if redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
        redis.call('SET', KEYS[2], '1', 'EX', ARGV[3])
        redis.call('LPUSH', KEYS[1], ARGV[1])
        redis.call('LTRIM', KEYS[1], 0, tonumber(ARGV[2])-1)
        redis.call('EXPIRE', KEYS[1], ARGV[3])
        return 1
        """
        await self.redis.eval(script, 2, self.prefix + ":events", self.prefix + ":seen:" + event["id"], json.dumps(event), self.maximum, self.ttl)

    async def events(self, limit=100, namespace=None, kind=None):
        values = await self.redis.lrange(self.prefix + ":events", 0, self.maximum - 1)
        return await asyncio.to_thread(self._filter_events, values, limit, namespace, kind)

    def _filter_events(self, values, limit, namespace, kind):
        cutoff = datetime.now(timezone.utc).timestamp() - self.ttl
        result = []
        for value in values:
            event = json.loads(value)
            if datetime.fromisoformat(event["observed_at"]).timestamp() < cutoff:
                continue
            if namespace and namespace not in (event.get("source_pod", {}).get("namespace"), event.get("destination_pod", {}).get("namespace"), event.get('target', {}).get('namespace')):
                continue
            if kind and event["kind"] != kind:
                continue
            result.append(event)
        result.sort(key=lambda e:e.get("timestamp") or e["observed_at"],reverse=True)
        return result[:limit]

    async def graph(self, limit=1000, namespace=None):
        nodes, edges = {}, {}
        for event in await self.events(limit, namespace, "network"):
            ids = []
            for side in ("source_pod", "destination_pod"):
                ep = event[side]
                identity = f"{self.cluster}/{ep['namespace']}/{ep['pod']}" if ep["pod"] else f"{self.cluster}/ip/{ep.get('ip') or 'unknown'}"
                nodes.setdefault(identity, {"id": identity, **ep, "last_seen": event.get("timestamp") or event["observed_at"]})
                ids.append(identity)
            key = tuple(ids)
            edge = edges.setdefault(key, {"source": ids[0], "target": ids[1], "flow_records": 0, "http_requests": 0, "drops": 0})
            edge["flow_records"] += 1
            edge["http_requests"] += int(bool(event.get("http")) and event.get("l7_type") == "REQUEST")
            edge["drops"] += int(event.get("verdict") == "DROPPED")
        snapshot = json.loads(await self.redis.get(self.prefix + ':inventory') or '{}')
        for pod in snapshot.get('pods', []):
            if namespace and pod['namespace'] != namespace:
                continue
            identity = f"{self.cluster}/{pod['namespace']}/{pod['pod']}"
            nodes.setdefault(identity, {'id': identity, 'namespace': pod['namespace'], 'pod': pod['pod'],
                                        'ip': pod.get('pod_ip'), 'last_seen': snapshot.get('observed_at')})
            if pod.get('node'):
                node_id = self.cluster + '/node/' + pod['node']
                nodes.setdefault(node_id, {'id': node_id, 'namespace': '', 'pod': '', 'ip': pod['node'],
                                           'kind': 'node', 'last_seen': snapshot.get('observed_at')})
                edges[(identity, node_id, 'scheduled_on')] = {'source': identity, 'target': node_id,
                    'kind': 'topology', 'relationship': 'Scheduled on node',
                    'flow_records': 0, 'http_requests': 0, 'drops': 0}
        return {"nodes": list(nodes.values()), "edges": list(edges.values()), "sample_limit": limit,
                "note": "Solid links show observed flows; dashed links show pod scheduling from inventory, not network traffic."}

    async def follow(self, source, filename):
        """Follow mounted JSONL exports; persist byte offsets, retry rotation/errors."""
        path = Path(filename)
        key = self.prefix + ":cursor:" + source
        while True:
            try:
                stat = path.stat()
                cursor = json.loads(await self.redis.get(key) or '{}')
                offset = cursor.get("offset", 0) if cursor.get("inode") == stat.st_ino else 0
                if stat.st_size < offset:
                    offset = 0
                self.health[source] = {**self.health.get(source, {}), "state": "following", "path": filename}
                with path.open("rb") as stream:
                    stream.seek(offset)
                    for _ in range(250):
                        line = stream.readline(1048577)
                        if not line or not line.endswith(b"\n"):
                            break
                        if len(line) > 1048576:
                            raise ValueError("Exporter record exceeds 1 MiB")
                        try:
                            event = normalize(json.loads(line), source, self.cluster)
                            if event:
                                await self.save(event)
                                self.health[source]["last_event_at"] = event["observed_at"]
                        except (ValueError, TypeError, KeyError, AttributeError):
                            log.warning("Invalid %s record at offset %s", source, stream.tell() - len(line))
                        await self.redis.set(key, json.dumps({"inode": stat.st_ino, "offset": stream.tell()}))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.health[source] = {"state": "error", "error": str(exc), "path": filename}
                log.warning("%s telemetry collector: %s", source, exc)
            await asyncio.sleep(1)

    def start(self):
        tasks = []
        for source, variable in (("hubble", "HUBBLE_EXPORT_PATH"), ("tetragon", "TETRAGON_EXPORT_PATH"), ("audit", "POD_AUDIT_EXPORT_PATH")):
            path = os.getenv(variable)
            self.health[source] = {"state": "disabled"}
            if path:
                tasks.append(asyncio.create_task(self.follow(source, path)))
        return tasks
