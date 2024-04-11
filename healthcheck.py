import asyncio
import discord
from aiohttp import web

class HealthCheck():
        
    def __init__(self, client: discord.client, bot_max_latency: float = 0.5):
        self.client = client
        self.bot_max_latency = bot_max_latency
    
    def handle_health(self, request: web.Request):
        status = "healthy"

        if (
            self.client.latency > self.bot_max_latency  # Latency too high
            or self.client.user is None  # Not logged in
            or not self.client.is_ready()  # Client’s internal cache not ready
            or self.client.is_closed()  # The websocket connection is closed
        ):
            status = "unhealthy"

        return web.json_response({
            "status": status,
            "latency": self.client.latency,
        }, status = 200 if status == "healthy" else 500)

    async def serve(self, host: str = "localhost", port: int = 8080):
        app = web.Application()
        app.router.add_get('/health', self.handle_health)

        runner = web.AppRunner(app)

        # async def on_shutdown(app):
        #     asyncio.ensure_future(runner.cleanup())

        # app.on_shutdown.append(on_shutdown)

        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()

def start(
    client: discord.client, port: int = 8080, bot_max_latency: float = 0.5
) -> asyncio.base_events.Server:
    """Starts the health check server.
    Args:
        client: The discord.py client object to monitor
        port: The port to bind the TCP socket server to
        bot_max_latency: The maximum acceptable latency (in seconds) for the bots
            connection to Discord
    Returns:
        asyncio.base_events.Server: The Server object for the healthcheck server
    """
    host = "0.0.0.0"
    health_check = HealthCheck(client, bot_max_latency)

    return client.loop.create_task(health_check.serve(host, port))
