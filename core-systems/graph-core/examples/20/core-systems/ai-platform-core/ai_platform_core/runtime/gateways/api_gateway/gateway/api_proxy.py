# gateway/api_proxy.py

import asyncio
import logging
from typing import Dict, Any, Optional
import aiohttp

logger = logging.getLogger(__name__)

class APIProxyAgent:
    def __init__(self, name: str, target_url: str, timeout: int = 10):
        self.name = name
        self.target_url = target_url
        self.timeout = timeout
        self.session = aiohttp.ClientSession()
        self.metrics = {
            "requests_count": 0,
            "errors_count": 0,
            "average_response_time": 0.0
        }

    async def forward_request(self, method: str, path: str, headers: Optional[Dict[str, str]] = None, 
                              params: Optional[Dict[str, Any]] = None, data: Optional[Any] = None) -> Dict[str, Any]:
        url = f"{self.target_url}{path}"
        self.metrics["requests_count"] += 1

        try:
            async with self.session.request(method=method, url=url, headers=headers, params=params, data=data, timeout=self.timeout) as resp:
                resp_data = await resp.json()
                await self._update_response_time()
                return {
                    "status": resp.status,
                    "data": resp_data
                }
        except asyncio.TimeoutError:
            self.metrics["errors_count"] += 1
            logger.error(f"Timeout when proxying request to {url}")
            return {"status": 504, "error": "Gateway Timeout"}
        except Exception as e:
            self.metrics["errors_count"] += 1
            logger.error(f"Error when proxying request to {url}: {e}")
            return {"status": 502, "error": "Bad Gateway"}

    async def _update_response_time(self):
        # Dummy implementation for response time tracking
        pass

    async def close(self):
        await self.session.close()

# Управление пулом агентов

class APIProxyManager:
    def __init__(self):
        self.agents: Dict[str, APIProxyAgent] = {}

    def add_agent(self, name: str, target_url: str, timeout: int = 10):
        if name in self.agents:
            raise ValueError(f"Agent with name {name} already exists")
        self.agents[name] = APIProxyAgent(name, target_url, timeout)

    def remove_agent(self, name: str):
        if name in self.agents:
            agent = self.agents.pop(name)
            asyncio.create_task(agent.close())

    def get_agent(self, name: str) -> Optional[APIProxyAgent]:
        return self.agents.get(name)

    async def forward_to_agent(self, agent_name: str, method: str, path: str, headers=None, params=None, data=None):
        agent = self.get_agent(agent_name)
        if not agent:
            return {"status": 404, "error": "Agent Not Found"}
        return await agent.forward_request(method, path, headers, params, data)

