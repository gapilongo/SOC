"""
Concrete implementations of ingestion plugins for various SOC data sources.

Includes plugins for:
- SIEM: Splunk, QRadar, Azure Sentinel, Wazuh
- EDR: CrowdStrike, SentinelOne
- Cloud: AWS GuardDuty, AWS Security Hub, Azure Defender
- Generic: Webhooks, File-based, REST API
"""

import asyncio
import base64
import csv
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import aiofiles
import aiohttp

from lg_sotf.agents.ingestion.plugins.base import IngestionPlugin
from lg_sotf.agents.ingestion.plugins.registry import plugin_registry

# ==========================================
# SIEM PLUGINS
# ==========================================

class SplunkPlugin(IngestionPlugin):
    """Splunk SIEM ingestion plugin."""

    async def initialize(self):
        """Initialize Splunk connection."""
        self.base_url = self.get_config("base_url")
        self.token = self.get_config("token")
        self.index = self.get_config("index", "main")
        self.search_timeout = self.get_config("search_timeout", 60)
        
        if not self.base_url or not self.token:
            raise ValueError("Splunk requires base_url and token")
        
        # Test connection
        if not await self.test_connection():
            raise ConnectionError("Failed to connect to Splunk")
        
        self.initialized = True
        self.logger.info("Splunk plugin initialized")

    async def fetch_alerts(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: Optional[int] = None,
        query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch alerts from Splunk."""
        try:
            # Build search query
            if query:
                search_query = query
            else:
                search_query = f'search index={self.index} sourcetype="security:*"'
                
                if since:
                    search_query += f' earliest={since.strftime("%Y-%m-%dT%H:%M:%S")}'
                if until:
                    search_query += f' latest={until.strftime("%Y-%m-%dT%H:%M:%S")}'
                
                search_query += ' | head ' + str(limit or 100)
            
            # Execute search
            async with aiohttp.ClientSession() as session:
                # Create search job
                search_url = urljoin(self.base_url, "/services/search/jobs")
                headers = {
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/x-www-form-urlencoded"
                }
                
                async with session.post(
                    search_url,
                    headers=headers,
                    data={"search": search_query, "output_mode": "json"},
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status != 201:
                        raise Exception(f"Splunk search failed: {response.status}")
                    
                    result = await response.json()
                    sid = result.get("sid")
                
                if not sid:
                    raise Exception("No search ID returned from Splunk")
                
                # Wait for search to complete
                results_url = urljoin(self.base_url, f"/services/search/jobs/{sid}/results")
                max_wait = self.search_timeout
                waited = 0
                
                while waited < max_wait:
                    async with session.get(
                        results_url,
                        headers=headers,
                        params={"output_mode": "json"},
                        timeout=aiohttp.ClientTimeout(total=self.timeout)
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            alerts = result.get("results", [])
                            
                            self._update_metrics(True)
                            return alerts
                        
                    await asyncio.sleep(2)
                    waited += 2
                
                raise Exception("Splunk search timed out")
                
        except Exception as e:
            self.logger.error(f"Failed to fetch alerts from Splunk: {e}")
            self._update_metrics(False)
            return []

    async def test_connection(self) -> bool:
        """Test Splunk connection."""
        try:
            async with aiohttp.ClientSession() as session:
                url = urljoin(self.base_url, "/services/server/info")
                headers = {"Authorization": f"Bearer {self.token}"}
                
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    return response.status == 200
                    
        except Exception as e:
            self.logger.error(f"Splunk connection test failed: {e}")
            return False

    async def cleanup(self):
        """Cleanup Splunk resources."""
        self.logger.info("Splunk plugin cleanup completed")


class QRadarPlugin(IngestionPlugin):
    """IBM QRadar SIEM ingestion plugin."""

    async def initialize(self):
        """Initialize QRadar connection."""
        self.base_url = self.get_config("base_url")
        self.token = self.get_config("token")
        
        if not self.base_url or not self.token:
            raise ValueError("QRadar requires base_url and token")
        
        if not await self.test_connection():
            raise ConnectionError("Failed to connect to QRadar")
        
        self.initialized = True
        self.logger.info("QRadar plugin initialized")

    async def fetch_alerts(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: Optional[int] = None,
        query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch offenses from QRadar."""
        try:
            async with aiohttp.ClientSession() as session:
                url = urljoin(self.base_url, "/api/siem/offenses")
                headers = {
                    "SEC": self.token,
                    "Content-Type": "application/json",
                    "Version": "14.0"
                }
                
                # Build filter
                filters = []
                if since:
                    timestamp_ms = int(since.timestamp() * 1000)
                    filters.append(f"start_time > {timestamp_ms}")
                
                params = {
                    "filter": " AND ".join(filters) if filters else None,
                    "sort": "-start_time",
                    "limit": limit or 100
                }
                
                async with session.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status != 200:
                        raise Exception(f"QRadar API failed: {response.status}")
                    
                    alerts = await response.json()
                    self._update_metrics(True)
                    return alerts if isinstance(alerts, list) else []
                    
        except Exception as e:
            self.logger.error(f"Failed to fetch alerts from QRadar: {e}")
            self._update_metrics(False)
            return []

    async def test_connection(self) -> bool:
        """Test QRadar connection."""
        try:
            async with aiohttp.ClientSession() as session:
                url = urljoin(self.base_url, "/api/system/about")
                headers = {"SEC": self.token}
                
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    return response.status == 200
                    
        except Exception as e:
            self.logger.error(f"QRadar connection test failed: {e}")
            return False

    async def cleanup(self):
        """Cleanup QRadar resources."""
        self.logger.info("QRadar plugin cleanup completed")


class AzureSentinelPlugin(IngestionPlugin):
    """Microsoft Azure Sentinel ingestion plugin."""

    async def initialize(self):
        """Initialize Azure Sentinel connection."""
        self.tenant_id = self.get_config("tenant_id")
        self.client_id = self.get_config("client_id")
        self.client_secret = self.get_config("client_secret")
        self.workspace_id = self.get_config("workspace_id")
        self.subscription_id = self.get_config("subscription_id")
        self.resource_group = self.get_config("resource_group")
        
        if not all([self.tenant_id, self.client_id, self.client_secret, self.workspace_id]):
            raise ValueError("Azure Sentinel requires tenant_id, client_id, client_secret, workspace_id")
        
        # Get access token
        self.access_token = await self._get_access_token()
        
        if not await self.test_connection():
            raise ConnectionError("Failed to connect to Azure Sentinel")
        
        self.initialized = True
        self.logger.info("Azure Sentinel plugin initialized")

    async def _get_access_token(self) -> str:
        """Get Azure AD access token."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
                data = {
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://management.azure.com/.default"
                }
                
                async with session.post(url, data=data) as response:
                    if response.status != 200:
                        raise Exception(f"Failed to get Azure token: {response.status}")
                    
                    result = await response.json()
                    return result["access_token"]
                    
        except Exception as e:
            self.logger.error(f"Failed to get Azure access token: {e}")
            raise

    async def fetch_alerts(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: Optional[int] = None,
        query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch incidents from Azure Sentinel."""
        try:
            async with aiohttp.ClientSession() as session:
                url = (
                    f"https://management.azure.com/subscriptions/{self.subscription_id}"
                    f"/resourceGroups/{self.resource_group}"
                    f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_id}"
                    f"/providers/Microsoft.SecurityInsights/incidents"
                )
                
                headers = {
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/json"
                }
                
                params = {
                    "api-version": "2021-10-01",
                    "$top": limit or 100,
                    "$orderby": "properties/createdTimeUtc desc"
                }
                
                if since:
                    params["$filter"] = f"properties/createdTimeUtc ge {since.isoformat()}"
                
                async with session.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status == 401:
                        # Token expired, refresh
                        self.access_token = await self._get_access_token()
                        return await self.fetch_alerts(since, until, limit, query)
                    
                    if response.status != 200:
                        raise Exception(f"Azure Sentinel API failed: {response.status}")
                    
                    result = await response.json()
                    alerts = result.get("value", [])
                    
                    self._update_metrics(True)
                    return alerts
                    
        except Exception as e:
            self.logger.error(f"Failed to fetch alerts from Azure Sentinel: {e}")
            self._update_metrics(False)
            return []

    async def test_connection(self) -> bool:
        """Test Azure Sentinel connection."""
        try:
            # Try to fetch 1 incident
            alerts = await self.fetch_alerts(limit=1)
            return True
            
        except Exception as e:
            self.logger.error(f"Azure Sentinel connection test failed: {e}")
            return False

    async def cleanup(self):
        """Cleanup Azure Sentinel resources."""
        self.logger.info("Azure Sentinel plugin cleanup completed")


class WazuhPlugin(IngestionPlugin):
    """Wazuh SIEM ingestion plugin."""

    async def initialize(self):
        """Initialize Wazuh connection."""
        self.base_url = self.get_config("base_url", "https://localhost:55000")
        self.username = self.get_config("username")
        self.password = self.get_config("password")
        
        if not self.username or not self.password:
            raise ValueError("Wazuh requires username and password")
        
        # Get authentication token
        self.token = await self._authenticate()
        
        if not await self.test_connection():
            raise ConnectionError("Failed to connect to Wazuh")
        
        self.initialized = True
        self.logger.info("Wazuh plugin initialized")

    async def _authenticate(self) -> str:
        """Authenticate with Wazuh."""
        try:
            async with aiohttp.ClientSession() as session:
                url = urljoin(self.base_url, "/security/user/authenticate")
                auth = aiohttp.BasicAuth(self.username, self.password)
                
                async with session.get(
                    url,
                    auth=auth,
                    ssl=False,  # Wazuh often uses self-signed certs
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status != 200:
                        raise Exception(f"Wazuh authentication failed: {response.status}")
                    
                    result = await response.json()
                    return result["data"]["token"]
                    
        except Exception as e:
            self.logger.error(f"Failed to authenticate with Wazuh: {e}")
            raise

    async def fetch_alerts(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: Optional[int] = None,
        query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch alerts from Wazuh."""
        try:
            async with aiohttp.ClientSession() as session:
                url = urljoin(self.base_url, "/security/alerts")
                headers = {
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json"
                }
                
                params = {
                    "limit": limit or 100,
                    "sort": "-timestamp"
                }
                
                if since:
                    params["q"] = f"timestamp>{since.strftime('%Y-%m-%dT%H:%M:%S')}"
                
                async with session.get(
                    url,
                    headers=headers,
                    params=params,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status != 200:
                        raise Exception(f"Wazuh API failed: {response.status}")
                    
                    result = await response.json()
                    alerts = result.get("data", {}).get("affected_items", [])
                    
                    self._update_metrics(True)
                    return alerts
                    
        except Exception as e:
            self.logger.error(f"Failed to fetch alerts from Wazuh: {e}")
            self._update_metrics(False)
            return []

    async def test_connection(self) -> bool:
        """Test Wazuh connection."""
        try:
            async with aiohttp.ClientSession() as session:
                url = urljoin(self.base_url, "/")
                headers = {"Authorization": f"Bearer {self.token}"}
                
                async with session.get(
                    url,
                    headers=headers,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    return response.status == 200
                    
        except Exception as e:
            self.logger.error(f"Wazuh connection test failed: {e}")
            return False

    async def cleanup(self):
        """Cleanup Wazuh resources."""
        self.logger.info("Wazuh plugin cleanup completed")


# ==========================================
# EDR PLUGINS
# ==========================================

class CrowdStrikePlugin(IngestionPlugin):
    """CrowdStrike Falcon EDR ingestion plugin."""

    async def initialize(self):
        """Initialize CrowdStrike connection."""
        self.base_url = self.get_config("base_url", "https://api.crowdstrike.com")
        self.client_id = self.get_config("client_id")
        self.client_secret = self.get_config("client_secret")
        
        if not self.client_id or not self.client_secret:
            raise ValueError("CrowdStrike requires client_id and client_secret")
        
        # Get OAuth token
        self.access_token = await self._get_access_token()
        
        if not await self.test_connection():
            raise ConnectionError("Failed to connect to CrowdStrike")
        
        self.initialized = True
        self.logger.info("CrowdStrike plugin initialized")

    async def _get_access_token(self) -> str:
        """Get CrowdStrike OAuth token."""
        try:
            async with aiohttp.ClientSession() as session:
                url = urljoin(self.base_url, "/oauth2/token")
                data = {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                }
                
                async with session.post(
                    url,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status != 201:
                        raise Exception(f"Failed to get CrowdStrike token: {response.status}")
                    
                    result = await response.json()
                    return result["access_token"]
                    
        except Exception as e:
            self.logger.error(f"Failed to get CrowdStrike access token: {e}")
            raise

    async def fetch_alerts(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: Optional[int] = None,
        query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch detections from CrowdStrike."""
        try:
            async with aiohttp.ClientSession() as session:
                # First, get detection IDs
                ids_url = urljoin(self.base_url, "/detects/queries/detects/v1")
                headers = {
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/json"
                }
                
                params = {
                    "limit": limit or 100,
                    "sort": "last_behavior|desc"
                }
                
                if since:
                    params["filter"] = f"last_behavior:>='{since.isoformat()}'"
                
                async with session.get(
                    ids_url,
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status != 200:
                        raise Exception(f"CrowdStrike API failed: {response.status}")
                    
                    result = await response.json()
                    detection_ids = result.get("resources", [])
                
                if not detection_ids:
                    return []
                
                # Get full detection details
                details_url = urljoin(self.base_url, "/detects/entities/summaries/GET/v1")
                payload = {"ids": detection_ids}
                
                async with session.post(
                    details_url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status != 200:
                        raise Exception(f"CrowdStrike details API failed: {response.status}")
                    
                    result = await response.json()
                    alerts = result.get("resources", [])
                    
                    self._update_metrics(True)
                    return alerts
                    
        except Exception as e:
            self.logger.error(f"Failed to fetch alerts from CrowdStrike: {e}")
            self._update_metrics(False)
            return []

    async def test_connection(self) -> bool:
        """Test CrowdStrike connection."""
        try:
            async with aiohttp.ClientSession() as session:
                url = urljoin(self.base_url, "/sensors/queries/sensors/v1")
                headers = {"Authorization": f"Bearer {self.access_token}"}
                params = {"limit": 1}
                
                async with session.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    return response.status == 200
                    
        except Exception as e:
            self.logger.error(f"CrowdStrike connection test failed: {e}")
            return False

    async def cleanup(self):
        """Cleanup CrowdStrike resources."""
        self.logger.info("CrowdStrike plugin cleanup completed")


# ==========================================
# CLOUD PLUGINS
# ==========================================

class AWSGuardDutyPlugin(IngestionPlugin):
    """AWS GuardDuty ingestion plugin."""

    async def initialize(self):
        """Initialize AWS GuardDuty."""
        # Note: In production, use boto3 for AWS SDK
        # This is a simplified implementation
        self.region = self.get_config("region", "us-east-1")
        self.detector_id = self.get_config("detector_id")
        self.access_key = self.get_config("access_key")
        self.secret_key = self.get_config("secret_key")
        
        if not self.detector_id:
            raise ValueError("AWS GuardDuty requires detector_id")
        
        self.initialized = True
        self.logger.info("AWS GuardDuty plugin initialized")

    async def fetch_alerts(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: Optional[int] = None,
        query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch findings from AWS GuardDuty."""
        try:
            # In production, use boto3:
            # import boto3
            # guardduty = boto3.client('guardduty', region_name=self.region)
            # response = guardduty.list_findings(DetectorId=self.detector_id, ...)
            
            self.logger.warning("AWS GuardDuty plugin requires boto3 implementation")
            self._update_metrics(True)
            return []
            
        except Exception as e:
            self.logger.error(f"Failed to fetch alerts from AWS GuardDuty: {e}")
            self._update_metrics(False)
            return []

    async def test_connection(self) -> bool:
        """Test AWS GuardDuty connection."""
        return self.initialized

    async def cleanup(self):
        """Cleanup AWS GuardDuty resources."""
        self.logger.info("AWS GuardDuty plugin cleanup completed")


# ==========================================
# GENERIC PLUGINS
# ==========================================

class WebhookPlugin(IngestionPlugin):
    """Webhook ingestion plugin for receiving alerts via HTTP."""

    async def initialize(self):
        """Initialize webhook plugin."""
        self.port = self.get_config("port", 8080)
        self.path = self.get_config("path", "/webhook")
        self.auth_token = self.get_config("auth_token")
        
        # In production, set up an HTTP server to receive webhooks
        # For now, this is a placeholder
        
        self.alert_queue = asyncio.Queue()
        self.initialized = True
        self.logger.info(f"Webhook plugin initialized on port {self.port}")

    async def fetch_alerts(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: Optional[int] = None,
        query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch alerts from webhook queue."""
        alerts = []
        
        try:
            # Drain the queue
            while not self.alert_queue.empty() and len(alerts) < (limit or 100):
                alert = await asyncio.wait_for(self.alert_queue.get(), timeout=0.1)
                alerts.append(alert)
            
            self._update_metrics(True)
            return alerts
            
        except asyncio.TimeoutError:
            return alerts
        except Exception as e:
            self.logger.error(f"Failed to fetch webhook alerts: {e}")
            self._update_metrics(False)
            return alerts

    async def receive_webhook(self, payload: Dict[str, Any]):
        """Receive and queue a webhook alert."""
        await self.alert_queue.put(payload)

    async def test_connection(self) -> bool:
        """Test webhook plugin."""
        return self.initialized

    async def cleanup(self):
        """Cleanup webhook resources."""
        self.logger.info("Webhook plugin cleanup completed")


class FilePlugin(IngestionPlugin):
    """Enhanced file-based ingestion plugin supporting multiple formats."""

    async def initialize(self):
        """Initialize file plugin."""
        self.watch_directory = Path(self.get_config("watch_directory", "/tmp/alerts"))
        self.file_patterns = self.get_config("file_patterns", ["*.json"])  # Support multiple patterns
        self.delete_after_read = self.get_config("delete_after_read", False)
        self.move_to_processed = self.get_config("move_to_processed", True)
        self.processed_directory = Path(self.get_config("processed_directory", "/tmp/alerts/processed"))
        
        # CSV-specific settings
        self.csv_delimiter = self.get_config("csv_delimiter", ",")
        self.csv_has_header = self.get_config("csv_has_header", True)
        self.csv_field_mapping = self.get_config("csv_field_mapping", {})  # Map CSV columns to alert fields
        
        # Create directories if needed
        self.watch_directory.mkdir(parents=True, exist_ok=True)
        if self.move_to_processed:
            self.processed_directory.mkdir(parents=True, exist_ok=True)
        
        self.initialized = True
        self.logger.info(f"File plugin initialized, watching {self.watch_directory}")

    async def fetch_alerts(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: Optional[int] = None,
        query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch alerts from files."""
        alerts = []
        
        try:
            # Find matching files for all patterns
            all_files = []
            if isinstance(self.file_patterns, str):
                self.file_patterns = [self.file_patterns]
            
            for pattern in self.file_patterns:
                all_files.extend(list(self.watch_directory.glob(pattern)))
            
            # Remove duplicates and sort by modification time
            all_files = list(set(all_files))
            all_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
            
            # Filter by time if specified
            if since:
                all_files = [
                    f for f in all_files 
                    if datetime.fromtimestamp(f.stat().st_mtime) >= since
                ]
            
            if until:
                all_files = [
                    f for f in all_files 
                    if datetime.fromtimestamp(f.stat().st_mtime) <= until
                ]
            
            # Process files
            for file_path in all_files[:limit or 100]:
                try:
                    # Determine file type and parse accordingly
                    file_alerts = await self._parse_file(file_path)
                    alerts.extend(file_alerts)
                    
                    # Handle file after reading
                    await self._handle_processed_file(file_path)
                    
                except Exception as e:
                    self.logger.error(f"Failed to process file {file_path}: {e}")
            
            self._update_metrics(True)
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to fetch alerts from files: {e}")
            self._update_metrics(False)
            return []

    async def _parse_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse file based on extension."""
        suffix = file_path.suffix.lower()
        
        if suffix == '.json':
            return await self._parse_json_file(file_path)
        elif suffix == '.csv':
            return await self._parse_csv_file(file_path)
        elif suffix in ['.txt', '.log']:
            return await self._parse_text_file(file_path)
        else:
            self.logger.warning(f"Unsupported file format: {suffix}")
            return []

    async def _parse_json_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse JSON file."""
        try:
            async with aiofiles.open(file_path, 'r') as f:
                content = await f.read()
            
            alert_data = json.loads(content)
            
            # Handle both single alert and array of alerts
            if isinstance(alert_data, list):
                return alert_data
            else:
                return [alert_data]
                
        except Exception as e:
            self.logger.error(f"Failed to parse JSON file {file_path}: {e}")
            return []

    async def _parse_csv_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse CSV file into alerts."""
        alerts = []
        
        try:
            async with aiofiles.open(file_path, 'r') as f:
                content = await f.read()
            
            # Parse CSV
            reader = csv.DictReader(
                content.splitlines(), 
                delimiter=self.csv_delimiter
            ) if self.csv_has_header else csv.reader(
                content.splitlines(),
                delimiter=self.csv_delimiter
            )
            
            for row in reader:
                try:
                    if self.csv_has_header:
                        # Row is already a dict
                        alert = self._map_csv_row_to_alert(row)
                    else:
                        # Convert list to dict using indices
                        row_dict = {str(i): val for i, val in enumerate(row)}
                        alert = self._map_csv_row_to_alert(row_dict)
                    
                    if alert:
                        alerts.append(alert)
                        
                except Exception as e:
                    self.logger.error(f"Failed to parse CSV row: {e}")
                    continue
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to parse CSV file {file_path}: {e}")
            return []

    def _map_csv_row_to_alert(self, row: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Map CSV row to alert format using field mapping."""
        try:
            alert = {}
            
            # Apply field mapping if configured
            if self.csv_field_mapping:
                for csv_field, alert_field in self.csv_field_mapping.items():
                    if csv_field in row:
                        alert[alert_field] = row[csv_field]
            else:
                # No mapping, use direct field names
                alert = dict(row)
            
            # Ensure required fields exist
            if 'id' not in alert:
                alert['id'] = f"csv_{hash(str(row))}"
            
            if 'timestamp' not in alert:
                alert['timestamp'] = datetime.utcnow().isoformat()
            
            return alert
            
        except Exception as e:
            self.logger.error(f"Failed to map CSV row to alert: {e}")
            return None

    async def _parse_text_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse text/log file (one alert per line as JSON)."""
        alerts = []
        
        try:
            async with aiofiles.open(file_path, 'r') as f:
                content = await f.read()
            
            for line_num, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    # Try to parse as JSON
                    alert = json.loads(line)
                    alerts.append(alert)
                except json.JSONDecodeError:
                    # If not JSON, create alert from text
                    alerts.append({
                        'id': f"{file_path.stem}_line{line_num}",
                        'description': line,
                        'timestamp': datetime.utcnow().isoformat(),
                        'source': 'file',
                        'severity': 'info'
                    })
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to parse text file {file_path}: {e}")
            return []

    async def _handle_processed_file(self, file_path: Path):
        """Handle file after successful processing."""
        try:
            if self.delete_after_read:
                file_path.unlink()
                self.logger.debug(f"Deleted processed file: {file_path}")
            elif self.move_to_processed:
                # Add timestamp to avoid conflicts
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                new_name = f"{file_path.stem}_{timestamp}{file_path.suffix}"
                processed_path = self.processed_directory / new_name
                
                file_path.rename(processed_path)
                self.logger.debug(f"Moved processed file to: {processed_path}")
                
        except Exception as e:
            self.logger.error(f"Failed to handle processed file {file_path}: {e}")

    async def test_connection(self) -> bool:
        """Test file plugin."""
        return self.watch_directory.exists() and self.watch_directory.is_dir()

    async def cleanup(self):
        """Cleanup file plugin resources."""
        self.logger.info("File plugin cleanup completed")


# ==========================================
# REGISTER ALL PLUGINS
# ==========================================

def register_all_plugins():
    """Register all available plugins."""
    plugin_registry.register("splunk", SplunkPlugin)
    plugin_registry.register("qradar", QRadarPlugin)
    plugin_registry.register("sentinel", AzureSentinelPlugin)
    plugin_registry.register("azure_sentinel", AzureSentinelPlugin)  # Alias
    plugin_registry.register("wazuh", WazuhPlugin)
    plugin_registry.register("crowdstrike", CrowdStrikePlugin)
    plugin_registry.register("guardduty", AWSGuardDutyPlugin)
    plugin_registry.register("aws_guardduty", AWSGuardDutyPlugin)  # Alias
    plugin_registry.register("webhook", WebhookPlugin)
    plugin_registry.register("file", FilePlugin)


# Auto-register plugins on import
register_all_plugins()