# agents/base_agent.py

import requests
import redis
import time
import threading
import os
import json
import psycopg2

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from dotenv import load_dotenv
from pydantic import ValidationError

from shared.constants import (
    REDIS_AGENT_HEARTBEAT,
    AGENT_HEARTBEAT_INTERVAL,
    AGENT_HEARTBEAT_TTL,
)

from shared.models import AgentResult


load_dotenv()


class BaseAgent(ABC):

    def __init__(self, agent_name: str):

        # ============================================================
        # BASIC AGENT CONFIG
        # ============================================================

        self.agent_name = agent_name

        self.orchestrator_url = os.getenv(
            "ORCHESTRATOR_URL",
            "http://100.82.97.75:8000"
        )

        # ============================================================
        # REDIS
        # ============================================================

        self.redis_client = redis.Redis(
            host=os.getenv(
                "REDIS_HOST",
                "localhost"
            ),
            port=int(
                os.getenv(
                    "REDIS_PORT",
                    6379
                )
            ),
            decode_responses=True
        )

        # ============================================================
        # POSTGRESQL
        # ============================================================

        self.postgres_dsn = os.getenv(
            "POSTGRES_DSN",
            ""
        )

        self.postgres_host = os.getenv(
            "POSTGRES_HOST",
            ""
        )

        self.postgres_port = int(
            os.getenv(
                "POSTGRES_PORT",
                5432
            )
        )

        self.postgres_db = os.getenv(
            "POSTGRES_DB",
            ""
        )

        self.postgres_user = os.getenv(
            "POSTGRES_USER",
            ""
        )

        self.postgres_password = os.getenv(
            "POSTGRES_PASSWORD",
            ""
        )

        # ============================================================
        # RUNTIME
        # ============================================================

        self.running = False

        self.heartbeat_interval = (
            AGENT_HEARTBEAT_INTERVAL
        )

        self.heartbeat_ttl = (
            AGENT_HEARTBEAT_TTL
        )

        self.poll_interval = 5

        # Poll-failure tracking. This is the actual fix: previously
        # _poll_for_tasks() swallowed every exception (network drop,
        # timeout, DNS failure - exactly what happens when a laptop's
        # WiFi adapter sleeps or Tailscale drops overnight) and
        # returned [] with zero output, which is indistinguishable
        # from "polled fine, nothing pending." That silence was why
        # the agent side looked "connected and polling" all night
        # while the Orchestrator saw nothing arrive at all. Now a
        # failed poll is loud, and a long silent gap becomes visible
        # in the logs after the fact instead of invisible.
        self.consecutive_poll_failures = 0
        self.last_successful_poll = None
        self._poll_cycle_count = 0

        # ============================================================
        # TASK CLAIMING (for Watchdog orphan detection)
        # ============================================================
        # This system dispatches tasks via HTTP poll against the
        # Orchestrator's /agents/{name}/tasks endpoint (which scans
        # task_status:{id} keys in Redis), not via a raw per-agent
        # Redis LPOP queue - so the literal
        # "RPOPLPUSH agent:{name}:pending_tasks agent:{name}:in_progress"
        # pattern doesn't map onto this codebase directly. What DOES
        # map: maintaining an agent:{name}:in_progress Redis list
        # ourselves, the moment a task is received over HTTP, with a
        # claimed_at timestamp embedded - so the Watchdog can LRANGE
        # this list on Redis and detect orphaned tasks the same way
        # it would if we'd popped them via RPOPLPUSH.
        #
        # IMPORTANT for whoever builds the Watchdog: "requeue" in this
        # system does NOT mean pushing the task back onto a Redis list
        # for us to re-pop - there is no such queue driving dispatch.
        # It means resetting task_status:{task_id} back to "pending"
        # in Redis, which is what the Orchestrator's existing
        # get_agent_tasks() already checks on every poll. That alone
        # is enough to make the task dispatchable again once this
        # agent (or a restarted instance of it) polls next.
        self.in_progress_key = f"agent:{self.agent_name}:in_progress"

        # How long a claimed task can sit in in_progress before the
        # Watchdog should consider it orphaned (only once this
        # agent's heartbeat has also gone stale - a claimed task with
        # a live heartbeat just means the agent is legitimately still
        # working). Override per-agent via env var: Investigation
        # legitimately runs longer than Triage (VirusTotal rate
        # limiting alone sleeps up to 15s per call, plus MISP +
        # Elasticsearch queries on top), so don't assume one global
        # number fits every agent - set TASK_ORPHAN_SECONDS higher in
        # Investigation's own .env if 120s proves too tight for it.
        self.task_orphan_seconds = int(
            os.getenv("TASK_ORPHAN_SECONDS", "120")
        )

        # ============================================================
        # STARTUP LOGGING
        # ============================================================

        print(
            f"[{self.agent_name}] Initialized"
        )

        print(
            f"[{self.agent_name}] "
            f"Orchestrator: {self.orchestrator_url}"
        )

        # Test PostgreSQL connection at startup.
        self._test_postgres_connection()

    # ================================================================
    # POSTGRES CONNECTION
    # ================================================================

    def _get_postgres_connection(self):

        """
        Create a PostgreSQL connection.

        Preferred:
            POSTGRES_DSN

        Otherwise:
            POSTGRES_HOST
            POSTGRES_PORT
            POSTGRES_DB
            POSTGRES_USER
            POSTGRES_PASSWORD
        """

        try:

            # --------------------------------------------------------
            # Option 1: DSN
            # --------------------------------------------------------

            if self.postgres_dsn:

                return psycopg2.connect(
                    self.postgres_dsn
                )

            # --------------------------------------------------------
            # Option 2: individual variables
            # --------------------------------------------------------

            if not all([
                self.postgres_host,
                self.postgres_db,
                self.postgres_user
            ]):

                return None

            return psycopg2.connect(
                host=self.postgres_host,
                port=self.postgres_port,
                dbname=self.postgres_db,
                user=self.postgres_user,
                password=self.postgres_password
            )

        except Exception as e:

            print(
                f"[{self.agent_name}] "
                f"PostgreSQL connection error: {e}"
            )

            return None

    # ================================================================
    # TEST POSTGRES
    # ================================================================

    def _test_postgres_connection(self):

        """
        Test PostgreSQL availability.

        PostgreSQL is optional for agent execution.
        If it is unavailable, the agent continues running.
        """

        connection = None

        try:

            connection = (
                self._get_postgres_connection()
            )

            if connection is None:

                print(
                    f"[{self.agent_name}] "
                    f"PostgreSQL: not configured"
                )

                return

            cursor = connection.cursor()

            cursor.execute(
                "SELECT 1"
            )

            cursor.fetchone()

            cursor.close()
            connection.close()

            print(
                f"[{self.agent_name}] "
                f"PostgreSQL: connected"
            )

        except Exception as e:

            print(
                f"[{self.agent_name}] "
                f"PostgreSQL test failed: {e}"
            )

            if connection:

                try:
                    connection.close()
                except Exception:
                    pass

    # ================================================================
    # EXPECTED STATE
    # ================================================================

    def record_expected_state(
        self,
        incident_id: str,
        check_type: str,
        target: str,
        expected_value: dict
    ) -> bool:

        """
        Insert an expected state into PostgreSQL.

        This is used by Response and Containment agents.

        Example:

            incident_id = "inc-123"

            check_type = "ufw_rule"

            target = "10.0.2.15"

            expected_value = {
                "blocked_ip": "8.8.8.8",
                "rule_present": True
            }

        The Watchdog / Verification component can later
        compare the expected state with the actual state.
        """

        connection = None

        try:

            connection = (
                self._get_postgres_connection()
            )

            if connection is None:

                print(
                    f"[{self.agent_name}] "
                    f"Expected-state insert skipped: "
                    f"PostgreSQL unavailable"
                )

                return False

            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO expected_state (
                    incident_id,
                    check_type,
                    target,
                    expected_value,
                    created_at,
                    last_check_ok,
                    last_check_reason
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s::jsonb,
                    NOW(),
                    NULL,
                    NULL
                )
                """,
                (
                    incident_id,
                    check_type,
                    target,
                    json.dumps(
                        expected_value
                    )
                )
            )

            connection.commit()

            cursor.close()
            connection.close()

            print(
                f"[{self.agent_name}] "
                f"Expected state recorded: "
                f"{check_type} → {target}"
            )

            return True

        except Exception as e:

            print(
                f"[{self.agent_name}] "
                f"Expected-state insert failed: {e}"
            )

            if connection:

                try:
                    connection.rollback()
                    connection.close()
                except Exception:
                    pass

            return False

    # ================================================================
    # AUTOMATIC EXPECTED STATE EXTRACTION
    # ================================================================

    def _record_expected_states_from_result(
        self,
        result: dict
    ):

        """
        Automatically create expected_state records from
        Response and Containment agent results.

        This means you do NOT have to manually add PostgreSQL
        INSERT statements everywhere.

        Response examples:

            block_ip
            isolate_host
            disable_account
            kill_process

        Containment examples:

            block_ip_all_vms
        """

        try:

            if self.agent_name not in (
                "response",
                "containment"
            ):

                return

            output = result.get(
                "output",
                {}
            )

            incident_id = output.get(
                "incident_id"
            )

            if not incident_id:

                return

            # ========================================================
            # RESPONSE AGENT
            # ========================================================

            if self.agent_name == "response":

                actions = output.get(
                    "actions_taken",
                    []
                )

                for action in actions:

                    if not isinstance(
                        action,
                        dict
                    ):
                        continue

                    action_type = action.get(
                        "action"
                    )

                    success = action.get(
                        "success",
                        False
                    )

                    if not success:

                        continue

                    # ------------------------------------------------
                    # BLOCK IP
                    # ------------------------------------------------

                    if action_type == "block_ip":

                        target = action.get(
                            "target_vm",
                            ""
                        )

                        malicious_ip = action.get(
                            "malicious_ip",
                            ""
                        )

                        self.record_expected_state(
                            incident_id=incident_id,
                            check_type="ufw_rule",
                            target=target,
                            expected_value={
                                "action": "block_ip",
                                "malicious_ip": malicious_ip,
                                "rule_present": True
                            }
                        )

                    # ------------------------------------------------
                    # HOST ISOLATION
                    # ------------------------------------------------

                    elif action_type == "isolate_host":

                        agent_id = action.get(
                            "agent_id",
                            ""
                        )

                        self.record_expected_state(
                            incident_id=incident_id,
                            check_type="host_isolation",
                            target=agent_id,
                            expected_value={
                                "action": "isolate_host",
                                "isolated": True
                            }
                        )

                    # ------------------------------------------------
                    # ACCOUNT DISABLE
                    # ------------------------------------------------

                    elif action_type == "disable_account":

                        username = action.get(
                            "username",
                            ""
                        )

                        self.record_expected_state(
                            incident_id=incident_id,
                            check_type="account_disabled",
                            target=username,
                            expected_value={
                                "action": "disable_account",
                                "username": username,
                                "disabled": True
                            }
                        )

                    # ------------------------------------------------
                    # PROCESS KILL
                    # ------------------------------------------------

                    elif action_type == "kill_process":

                        target_vm = action.get(
                            "target_vm",
                            ""
                        )

                        pid = action.get(
                            "pid"
                        )

                        process_name = action.get(
                            "process_name",
                            ""
                        )

                        self.record_expected_state(
                            incident_id=incident_id,
                            check_type="process_killed",
                            target=target_vm,
                            expected_value={
                                "action": "kill_process",
                                "pid": pid,
                                "process_name": process_name,
                                "running": False
                            }
                        )

            # ========================================================
            # CONTAINMENT AGENT
            # ========================================================

            elif self.agent_name == "containment":

                containment_results = output.get(
                    "containment_results",
                    []
                )

                for containment in containment_results:

                    if not isinstance(
                        containment,
                        dict
                    ):
                        continue

                    # ------------------------------------------------
                    # BLOCK ALL VMS
                    # ------------------------------------------------

                    if containment.get(
                        "action"
                    ) == "block_ip_all_vms":

                        malicious_ip = containment.get(
                            "malicious_ip",
                            ""
                        )

                        vm_results = containment.get(
                            "vm_results",
                            []
                        )

                        for vm in vm_results:

                            if not isinstance(
                                vm,
                                dict
                            ):
                                continue

                            if not vm.get(
                                "success",
                                False
                            ):
                                continue

                            vm_ip = vm.get(
                                "vm_ip",
                                ""
                            )

                            vm_name = vm.get(
                                "vm",
                                vm_ip
                            )

                            self.record_expected_state(
                                incident_id=incident_id,
                                check_type="ufw_rule",
                                target=vm_name,
                                expected_value={
                                    "action": "block_ip",
                                    "malicious_ip": malicious_ip,
                                    "rule_present": True,
                                    "vm_ip": vm_ip
                                }
                            )

        except Exception as e:

            # Expected-state recording must NEVER
            # break the actual agent result submission.

            print(
                f"[{self.agent_name}] "
                f"Expected-state processing error: {e}"
            )

    # ================================================================
    # HEARTBEAT
    # ================================================================

    def _publish_heartbeat(self):

        heartbeat_key = (
            REDIS_AGENT_HEARTBEAT.format(
                name=self.agent_name
            )
        )

        while self.running:

            try:

                self.redis_client.setex(
                    heartbeat_key,
                    self.heartbeat_ttl,
                    "alive"
                )

            except Exception as e:

                print(
                    f"[{self.agent_name}] "
                    f"[{datetime.now().strftime('%H:%M:%S')}] "
                    f"Heartbeat error: {e}"
                )

            time.sleep(
                self.heartbeat_interval
            )

    # ================================================================
    # TASK CLAIMING - RPOPLPUSH equivalent for Watchdog visibility
    # ================================================================

    def _claim_task(self, task: dict) -> str:
        """
        Record that this agent has started working on a task, so the
        Watchdog can detect it as orphaned if this agent dies mid-task.

        Deliberately stores a LEAN record - task_id, incident_id,
        agent, action, claimed_at - not the full task dict (which can
        carry the entire incident_context, including raw_log). The
        Watchdog only needs enough to identify the task and compute
        its age; it doesn't need the full incident payload duplicated
        into this list on every claim.

        Returns the exact JSON string that was pushed, since LREM
        needs an exact value match to remove it later - this is the
        one thing callers must hang onto and pass to _release_task().
        """
        claim_record = {
            "task_id": task.get("task_id"),
            "incident_id": task.get("incident_id"),
            "agent": self.agent_name,
            "action": task.get("action"),
            "claimed_at": datetime.now(timezone.utc).isoformat(),
        }

        claim_json = json.dumps(claim_record, default=str)

        try:
            self.redis_client.lpush(self.in_progress_key, claim_json)
        except Exception as e:
            print(
                f"[{self.agent_name}] "
                f"Could not record task claim in Redis: {e}"
            )

        return claim_json

    def _release_task(self, claim_json: str):
        """
        Remove a task's claim record once it's finished - success or
        failure, doesn't matter, it's no longer "in progress" either
        way. Called from a finally block so this always runs even if
        execute_task() raises.
        """
        try:
            self.redis_client.lrem(self.in_progress_key, 1, claim_json)
        except Exception as e:
            print(
                f"[{self.agent_name}] "
                f"Could not release task claim in Redis: {e}"
            )

    # ================================================================
    # INCIDENT CONTEXT
    # ================================================================

    def get_incident_context(
        self,
        incident_id: str
    ) -> dict:

        try:

            response = requests.get(
                f"{self.orchestrator_url}"
                f"/incidents/{incident_id}/context",
                timeout=(10,30)
            )

            if response.status_code == 200:

                return response.json()

            print(
                f"[{self.agent_name}] "
                f"Could not get context for "
                f"{incident_id}: "
                f"{response.status_code}"
            )

            return {}

        except Exception as e:

            print(
                f"[{self.agent_name}] "
                f"Error getting context: {e}"
            )

            return {}

    # ================================================================
    # SUBMIT RESULT
    # ================================================================

    def submit_result(
        self,
        result: dict
    ) -> bool:

        result["agent_name"] = (
            self.agent_name
        )

        result.setdefault(
            "timestamp",
            datetime.now(timezone.utc)
        )

        # ------------------------------------------------------------
        # VALIDATE RESULT
        # ------------------------------------------------------------

        try:

            validated = AgentResult(
                **result
            )

        except ValidationError as e:

            print(
                f"[{self.agent_name}] "
                f"Result failed schema validation, "
                f"not submitting:\n{e}"
            )

            return False

        # ------------------------------------------------------------
        # RECORD EXPECTED STATE
        #
        # Do this BEFORE sending the result to the orchestrator.
        # If PostgreSQL fails, the agent still submits its result.
        # ------------------------------------------------------------

        try:

            validated_dict = (
                validated.model_dump()
            )

            self._record_expected_states_from_result(
                validated_dict
            )

        except Exception as e:

            print(
                f"[{self.agent_name}] "
                f"Expected-state recording error: {e}"
            )

        # ------------------------------------------------------------
        # SUBMIT TO ORCHESTRATOR
        # ------------------------------------------------------------

        try:

            payload = (
                validated.model_dump(mode="json")
            )

            response = requests.post(
                f"{self.orchestrator_url}"
                f"/orchestrator/results",
                json=payload,
                timeout=10
            )

            if response.status_code == 200:

                print(
                    f"[{self.agent_name}] "
                    f"Result submitted for task "
                    f"{validated.task_id}"
                )

                return True

            print(
                f"[{self.agent_name}] "
                f"Failed to submit result: "
                f"{response.status_code}"
            )

            return False

        except Exception as e:

            print(
                f"[{self.agent_name}] "
                f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"Error submitting result (connection issue?): {e}"
            )

            return False

    # ================================================================
    # POLL FOR TASKS
    # ================================================================

    def _poll_for_tasks(self) -> list:

        """
        THE FIX: this previously had `except Exception: return []`
        with no logging at all, making a dead connection completely
        indistinguishable from "polled fine, nothing pending." That
        silence is why the agent side looked connected and polling
        all night while the Orchestrator saw nothing arrive - the
        request was actually failing every single cycle, silently.

        Now: a failed poll prints loudly (first failure, and then
        every 12 cycles / ~1 minute at default poll_interval=5 so a
        long outage doesn't scroll past unnoticed), and recovery
        after a run of failures prints how long the gap was.
        """

        now_str = datetime.now().strftime('%H:%M:%S')

        try:

            response = requests.get(
                f"{self.orchestrator_url}"
                f"/agents/{self.agent_name}/tasks",
                timeout=(10, 30)
            )

            if response.status_code == 200:

                # ---- Recovery after a run of failures ----
                if self.consecutive_poll_failures > 0:

                    print(
                        f"[{self.agent_name}] "
                        f"[{now_str}] Poll RECOVERED after "
                        f"{self.consecutive_poll_failures} failed "
                        f"attempt(s) "
                        f"(last success: {self.last_successful_poll})"
                    )

                self.consecutive_poll_failures = 0
                self.last_successful_poll = now_str

                return response.json().get(
                    "tasks",
                    []
                )

            # ---- Non-200 response (server up, but returned an error) ----
            self.consecutive_poll_failures += 1

            print(
                f"[{self.agent_name}] "
                f"[{now_str}] Poll returned HTTP "
                f"{response.status_code} "
                f"(consecutive failures: "
                f"{self.consecutive_poll_failures})"
            )

            return []

        except Exception as e:

            # ---- Connection-level failure: refused, timeout, DNS,
            #      network adapter asleep, Tailscale down, etc. ----
            self.consecutive_poll_failures += 1

            # Print the first failure immediately, then only every
            # 12th cycle after that (~1 min at 5s poll_interval) so
            # an overnight outage doesn't spam thousands of identical
            # lines but is still clearly visible when scrolling logs.
            if (
                self.consecutive_poll_failures == 1
                or self.consecutive_poll_failures % 12 == 0
            ):

                print(
                    f"[{self.agent_name}] "
                    f"[{now_str}] POLL FAILED (connection error): "
                    f"{e} "
                    f"(consecutive failures: "
                    f"{self.consecutive_poll_failures}, "
                    f"last success: {self.last_successful_poll})"
                )

            return []

    # ================================================================
    # ABSTRACT TASK EXECUTION
    # ================================================================

    @abstractmethod
    def execute_task(
        self,
        task: dict,
        incident_context: dict
    ) -> dict:

        pass

    # ================================================================
    # MAIN RUN LOOP
    # ================================================================

    def run(self):

        self.running = True

        # ------------------------------------------------------------
        # HEARTBEAT THREAD
        # ------------------------------------------------------------

        heartbeat_thread = threading.Thread(
            target=self._publish_heartbeat,
            daemon=True,
            name=f"{self.agent_name}-heartbeat"
        )

        heartbeat_thread.start()

        print(
            f"\n[{self.agent_name}] "
            f"Started successfully"
        )

        print(
            f"[{self.agent_name}] "
            f"Polling every "
            f"{self.poll_interval} seconds"
        )

        print(
            f"[{self.agent_name}] "
            f"Press Ctrl+C to stop\n"
        )

        # ------------------------------------------------------------
        # POLLING LOOP
        # ------------------------------------------------------------

        while self.running:

            try:

                tasks = (
                    self._poll_for_tasks()
                )

                self._poll_cycle_count += 1

                # Periodic "still alive" ping even when there's
                # nothing to do and no failures - roughly once every
                # 5 minutes at the default 5s poll_interval. This
                # means a totally silent multi-hour gap in the logs
                # (no heartbeat ping, no status ping, nothing) is
                # itself informative: if you don't even see these,
                # the whole process was likely suspended, not just
                # the network.
                if (
                    not tasks
                    and self.consecutive_poll_failures == 0
                    and self._poll_cycle_count % 60 == 0
                ):

                    print(
                        f"[{self.agent_name}] "
                        f"[{datetime.now().strftime('%H:%M:%S')}] "
                        f"still polling, no pending tasks "
                        f"(last success: {self.last_successful_poll})"
                    )

                if tasks:

                    print(
                        f"\n[{self.agent_name}] "
                        f"Received {len(tasks)} task(s)"
                    )

                for task in tasks:

                    task_id = task.get(
                        "task_id"
                    )

                    incident_id = task.get(
                        "incident_id"
                    )

                    action = task.get(
                        "action"
                    )

                    print(
                        f"[{self.agent_name}] "
                        f"Executing task "
                        f"{task_id}: "
                        f"{action}"
                    )

                    print(
                        f"[{self.agent_name}] "
                        f"Incident: "
                        f"{incident_id}"
                    )

                    # ------------------------------------------------
                    # GET INCIDENT CONTEXT
                    # ------------------------------------------------

                    incident_context = (
                        task.get(
                            "incident_context"
                        )
                        or self.get_incident_context(
                            incident_id
                        )
                    )

                    # ------------------------------------------------
                    # CLAIM TASK (for Watchdog orphan detection)
                    # ------------------------------------------------
                    # Claimed before execution starts, released in the
                    # finally block below so it's removed from
                    # in_progress no matter how execution ends -
                    # success, failure, or an unhandled exception.
                    claim_json = self._claim_task(task)

                    try:

                        try:

                            # ------------------------------------------------
                            # EXECUTE
                            # ------------------------------------------------

                            result = self.execute_task(
                                task,
                                incident_context
                            )

                            # ------------------------------------------------
                            # NORMALISE RESULT
                            # ------------------------------------------------

                            if not isinstance(
                                result,
                                dict
                            ):

                                result = {
                                    "task_id": task_id,
                                    "success": False,
                                    "output": {},
                                    "error_message": (
                                        "Agent returned "
                                        "non-dict result"
                                    )
                                }

                            result["task_id"] = (
                                task_id
                            )

                            result["success"] = (
                                result.get(
                                    "success",
                                    True
                                )
                            )

                            # ------------------------------------------------
                            # SUBMIT
                            # ------------------------------------------------

                            self.submit_result(
                                result
                            )

                        except Exception as e:

                            print(
                                f"[{self.agent_name}] "
                                f"Task execution error: "
                                f"{e}"
                            )

                            self.submit_result(
                                {
                                    "task_id": task_id,
                                    "success": False,
                                    "error_message": str(e),
                                    "output": {}
                                }
                            )

                    finally:

                        # Always release the claim, regardless of how
                        # the task ended - this is what keeps
                        # in_progress accurate for the Watchdog.
                        self._release_task(claim_json)

            except KeyboardInterrupt:

                print(
                    f"\n[{self.agent_name}] "
                    f"Stopping..."
                )

                self.running = False

                break

            except Exception as e:

                print(
                    f"[{self.agent_name}] "
                    f"Polling error: {e}"
                )

            time.sleep(
                self.poll_interval
            )

        print(
            f"[{self.agent_name}] "
            f"Stopped"
        )

    # ================================================================
    # STOP
    # ================================================================

    def stop(self):

        self.running = False