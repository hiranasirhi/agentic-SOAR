# agents/investigation_agent.py

from agents.base_agent import BaseAgent
from shared.constants import AGENT_INVESTIGATION
from opensearchpy import OpenSearch
import requests
import time
import os
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings()

class InvestigationAgent(BaseAgent):

    def __init__(self):
        super().__init__(AGENT_INVESTIGATION)

        # VirusTotal
        self.vt_api_key = os.getenv("VT_API_KEY", "")

        # MISP
        self.misp_url = os.getenv("MISP_URL", "")
        self.misp_api_key = os.getenv("MISP_API_KEY", "")

        # OpenSearch / Wazuh
        host = os.getenv("ELASTICSEARCH_URL", "https://localhost:9200")
        host = host.replace("https://", "").replace("http://", "")

        self.es = OpenSearch(
            hosts=[{
                "host": host.split(":")[0],
                "port": int(host.split(":")[1])
            }],
            http_auth=(
                os.getenv("ELASTICSEARCH_USER", "admin"),
                os.getenv("ELASTICSEARCH_PASS", "admin")
            ),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )

        # VirusTotal rate limiting
        self.vt_last_call = 0
        self.vt_min_interval = 15

        print(f"[{AGENT_INVESTIGATION}] VirusTotal: {'configured' if self.vt_api_key else 'NOT configured'}")
        print(f"[{AGENT_INVESTIGATION}] MISP: {'configured' if self.misp_url else 'NOT configured'}")
        
    # ============================================
    # VIRUSTOTAL API
    # ============================================

    def query_virustotal(self, ip_address: str) -> dict:
        if not self.vt_api_key:
            return {
                "source": "virustotal",
                "error": "API key not configured",
                "detection_ratio": 0,
                "reputation": "UNKNOWN"
            }

        time_since_last = time.time() - self.vt_last_call
        if time_since_last < self.vt_min_interval:
            wait_time = self.vt_min_interval - time_since_last
            print(f"[{AGENT_INVESTIGATION}] VT rate limit: waiting {wait_time:.1f}s")
            time.sleep(wait_time)

        try:
            print(f"[{AGENT_INVESTIGATION}] Querying VirusTotal for {ip_address}")

            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                headers=headers,
                timeout=15
            )

            self.vt_last_call = time.time()

            if response.status_code == 200:
                data = response.json()
                attrs = data["data"]["attributes"]
                stats = attrs.get("last_analysis_stats", {})

                total = sum(stats.values())
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                detection_ratio = (malicious + suspicious) / total if total > 0 else 0

                if malicious > 10:
                    reputation = "MALICIOUS"
                elif malicious > 3 or suspicious > 5:
                    reputation = "SUSPICIOUS"
                elif malicious > 0:
                    reputation = "LOW_RISK"
                else:
                    reputation = "CLEAN"

                result = {
                    "source": "virustotal",
                    "ip": ip_address,
                    "detection_ratio": round(detection_ratio, 3),
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "total_engines": total,
                    "reputation": reputation,
                    "country": attrs.get("country", "unknown"),
                    "as_owner": attrs.get("as_owner", "unknown")
                }

                print(f"[{AGENT_INVESTIGATION}] VT result: {reputation} ({malicious}/{total} engines)")
                return result

            elif response.status_code == 404:
                return {
                    "source": "virustotal",
                    "ip": ip_address,
                    "detection_ratio": 0,
                    "reputation": "NOT_FOUND",
                    "note": "IP not in VirusTotal database"
                }
            else:
                return {
                    "source": "virustotal",
                    "ip": ip_address,
                    "error": f"HTTP {response.status_code}",
                    "detection_ratio": 0,
                    "reputation": "UNKNOWN"
                }

        except Exception as e:
            print(f"[{AGENT_INVESTIGATION}] VT error: {e}")
            return {
                "source": "virustotal",
                "ip": ip_address,
                "error": str(e),
                "detection_ratio": 0,
                "reputation": "UNKNOWN"
            }

    # ============================================
    # MISP API
    # ============================================

    def query_misp(self, indicator: str) -> dict:
        if not self.misp_url or not self.misp_api_key:
            return {
                "source": "misp",
                "indicator": indicator,
                "found": False,
                "threat_level": "NONE",
                "error": "MISP not configured"
            }

        try:
            print(f"[{AGENT_INVESTIGATION}] Querying MISP for {indicator}")

            headers = {
                "Authorization": self.misp_api_key,
                "Accept": "application/json",
                "Content-Type": "application/json"
            }

            response = requests.post(
                f"{self.misp_url}/attributes/restSearch",
                headers=headers,
                json={
                    "value": indicator,
                    "limit": 10,
                    "returnFormat": "json"
                },
                timeout=15,
                verify=False
            )

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("response", {}).get("Attribute", [])

                match_count = len(attributes)

                if match_count >= 5:
                    threat_level = "HIGH"
                elif match_count >= 2:
                    threat_level = "MEDIUM"
                elif match_count >= 1:
                    threat_level = "LOW"
                else:
                    threat_level = "NONE"

                tags = []
                event_types = []
                for attr in attributes[:5]:
                    event_types.append(attr.get("type", "unknown"))
                    for tag in attr.get("Tag", []):
                        if tag.get("name"):
                            tags.append(tag["name"])

                result = {
                    "source": "misp",
                    "indicator": indicator,
                    "found": match_count > 0,
                    "match_count": match_count,
                    "threat_level": threat_level,
                    "threat_level_numeric": {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}.get(threat_level, 0),
                    "indicator_types": list(set(event_types)),
                    "tags": list(set(tags))[:5]
                }

                print(f"[{AGENT_INVESTIGATION}] MISP result: {threat_level} ({match_count} matches)")
                return result

            else:
                return {
                    "source": "misp",
                    "indicator": indicator,
                    "found": False,
                    "threat_level": "NONE",
                    "error": f"HTTP {response.status_code}"
                }

        except Exception as e:
            print(f"[{AGENT_INVESTIGATION}] MISP error: {e}")
            return {
                "source": "misp",
                "indicator": indicator,
                "found": False,
                "threat_level": "NONE",
                "error": str(e)
            }

    # ============================================
    # TI CONFIDENCE SCORE
    # ============================================

    def calculate_ti_confidence(self, vt_result: dict, misp_result: dict) -> float:
        vt_ratio = vt_result.get("detection_ratio", 0)
        misp_numeric = misp_result.get("threat_level_numeric", 0)

        if vt_result.get("error") and misp_result.get("error"):
            return None

        confidence = (vt_ratio * 0.6) + ((misp_numeric / 3) * 0.4)
        confidence = round(confidence, 3)

        print(f"[{AGENT_INVESTIGATION}] TI Confidence: {confidence}")
        print(f"  VT ratio: {vt_ratio} x 0.6 = {vt_ratio * 0.6:.3f}")
        print(f"  MISP level: {misp_numeric}/3 x 0.4 = {(misp_numeric/3)*0.4:.3f}")

        return confidence

    # ============================================
    # ELASTICSEARCH ATTACK TIMELINE
    # ============================================

    def build_attack_timeline(self, source_ip: str, hours: int = 24) -> list:
        try:
            print(f"[{AGENT_INVESTIGATION}] Building timeline for {source_ip} (last {hours}h)")

            response = self.es.search(
                index="soar-events",
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"source_ip": source_ip}},
                                {"range": {
                                    "timestamp": {
                                        "gte": f"now-{hours}h",
                                        "lte": "now"
                                    }
                                }}
                            ]
                        }
                    },
                    "sort": [{"timestamp": "asc"}],
                    "size": 100
                }
            )

            timeline = []
            for hit in response["hits"]["hits"]:
                event = hit["_source"]
                timeline.append({
    "timestamp": event.get("timestamp"),
    "event_type": event.get("rule_description"),
    "severity": event.get("severity"),
    "mitre_technique": event.get("mitre_technique"),
    "mitre_tactic": event.get("mitre_tactic"),
    "target_ip": event.get("destination_ip"),
    "hostname": event.get("hostname"),
    "username": event.get("username"),
    "source_tool": event.get("event_source")
})

            print(f"[{AGENT_INVESTIGATION}] Timeline: {len(timeline)} events found")
            return timeline

        except Exception as e:
            print(f"[{AGENT_INVESTIGATION}] Timeline error: {e}")
            return []

    # ============================================
    # LATERAL MOVEMENT DETECTION
    # ============================================

    def detect_lateral_movement(self, username: str, after_timestamp: str) -> dict:
        if not username or not after_timestamp:
            return {
                "detected": False,
                "affected_systems": [],
                "system_count": 0
            }

        try:
            print(f"[{AGENT_INVESTIGATION}] Checking lateral movement for user: {username}")

            response = self.es.search(
                index="soar-events",
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"username": username}},
                                {"range": {
                                    "timestamp": {"gte": after_timestamp}
                                }}
                            ]
                        }
                    },
                    "aggs": {
                        "unique_targets": {
                            "terms": {"field": "destination_ip"}
                        }
                    },
                    "size": 50
                }
            )

            unique_targets = set()
            for hit in response["hits"]["hits"]:
                target = hit["_source"].get("destination_ip")
                if target:
                    unique_targets.add(target)

            detected = len(unique_targets) > 1

            if detected:
                print(f"[{AGENT_INVESTIGATION}] LATERAL MOVEMENT detected! {len(unique_targets)} systems")
            else:
                print(f"[{AGENT_INVESTIGATION}] No lateral movement detected")

            return {
                "detected": detected,
                "affected_systems": list(unique_targets),
                "system_count": len(unique_targets)
            }

        except Exception as e:
            print(f"[{AGENT_INVESTIGATION}] Lateral movement check error: {e}")
            return {
                "detected": False,
                "affected_systems": [],
                "system_count": 0
            }

    # ============================================
    # EXECUTE TASK — Called by BaseAgent
    # ============================================

    def execute_task(self, task: dict, incident_context: dict) -> dict:
        """
        Returns only task_id, success, output - BaseAgent.submit_result()
        fills in agent_name and timestamp automatically, then validates
        against shared.models.AgentResult.
        """
        incident_id = task.get("incident_id", "UNKNOWN")
        source_ip = incident_context.get("source_ip", "")
        username = incident_context.get("username", "")

        print(f"\n[{AGENT_INVESTIGATION}] Investigating incident {incident_id}")
        print(f"[{AGENT_INVESTIGATION}] Source IP: {source_ip}")

        vt_result = self.query_virustotal(source_ip) if source_ip else {"detection_ratio": 0, "reputation": "UNKNOWN"}
        misp_result = self.query_misp(source_ip) if source_ip else {"found": False, "threat_level": "NONE"}
        ti_confidence = self.calculate_ti_confidence(vt_result, misp_result)
        timeline = self.build_attack_timeline(source_ip)

        lateral_movement = {"detected": False, "affected_systems": [], "system_count": 0}
        if username and timeline:
            first_event_time = timeline[0].get("timestamp", "now-1h") if timeline else "now-1h"
            lateral_movement = self.detect_lateral_movement(username, first_event_time)

        if ti_confidence is None:
            verdict = "UNKNOWN - ESCALATE"
        elif ti_confidence >= 0.7:
            verdict = "MALICIOUS - HIGH CONFIDENCE"
        elif ti_confidence >= 0.4:
            verdict = "SUSPICIOUS - INVESTIGATE FURTHER"
        else:
            verdict = "LOW CONFIDENCE - POSSIBLE FALSE POSITIVE"

        print(f"\n[{AGENT_INVESTIGATION}] Investigation complete:")
        print(f"  TI Confidence: {ti_confidence}")
        print(f"  Verdict: {verdict}")
        print(f"  Timeline events: {len(timeline)}")
        print(f"  Lateral movement: {lateral_movement['detected']}")

        return {
            "task_id": task.get("task_id"),
            "success": True,
            "output": {
                "ioc_reputation": {
                    "source_ip": source_ip,
                    "virustotal": vt_result,
                    "misp": misp_result,
                    "overall_verdict": verdict
                },
                "ti_confidence": ti_confidence,
                "threat_timeline": timeline,
                "timeline_event_count": len(timeline),
                "lateral_movement": lateral_movement,
                "lateral_movement_detected": lateral_movement["detected"],
                "affected_assets": lateral_movement["affected_systems"]
            }
        }


# Run investigation agent
if __name__ == "__main__":
    agent = InvestigationAgent()
    agent.run()