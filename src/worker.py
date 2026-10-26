"""Cloudflare Python Workers ASGI bridge. Nothing here deploys services."""

import asgi
from workers import WorkerEntrypoint

from agentshield.gateway import app


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        return await asgi.fetch(app, request, self.env)
