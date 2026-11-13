import asyncio


class WebSocketManager:
    """
    Manage active WebSocket connections and broadcast JSON events.
    """

    def __init__(self):
        self.active_connections = set()
        self._loop = None

    def register_loop(self, loop):
        """
        Register the running asyncio event loop used for broadcasts.
        """

        self._loop = loop

    def clear_loop(self):
        """
        Clear the registered event loop during application shutdown.
        """

        self._loop = None

    async def connect(self, websocket):
        """
        Accept a new WebSocket connection and track it.
        """

        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket):
        """
        Remove a WebSocket connection from the active set.
        """

        self.active_connections.discard(websocket)

    async def broadcast(self, event):
        """
        Send a JSON event to every connected client.

        Failed connections are removed without affecting the others.
        """

        failed_connections = []

        for websocket in list(self.active_connections):

            try:
                await websocket.send_json(event)

            except Exception:
                failed_connections.append(websocket)

        for websocket in failed_connections:
            self.disconnect(websocket)

    def broadcast_from_thread(self, event):
        """
        Schedule an async broadcast from a non-async thread.

        Returns True when the broadcast was scheduled, otherwise False.
        """

        loop = self._loop

        if loop is None or loop.is_closed() or not loop.is_running():
            return False

        try:
            loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(self.broadcast(event))
            )
            return True

        except RuntimeError:
            return False


websocket_manager = WebSocketManager()
