from app.services.websocket_manager import websocket_manager


def iso_timestamp(value):
    """
    Convert a datetime value into an ISO string.

    Naive SQLite timestamps are assumed to be UTC and receive a trailing Z.
    """

    if value is None:
        return None

    if value.tzinfo is None:
        return f"{value.isoformat()}Z"

    return value.isoformat()


def serialize_traffic(traffic):
    """
    Convert a Traffic record into a JSON-compatible dictionary.
    """

    return {
        "id": traffic.id,
        "source_ip": traffic.source_ip,
        "destination_ip": traffic.destination_ip,
        "protocol": traffic.protocol,
        "source_port": traffic.source_port,
        "destination_port": traffic.destination_port,
        "packet_size": traffic.packet_size,
        "timestamp": iso_timestamp(traffic.timestamp),
        "status": traffic.status,
        "direction": traffic.direction
    }


def serialize_alert(alert):
    """
    Convert an Alert record into a JSON-compatible dictionary.
    """

    return {
        "id": alert.id,
        "source_ip": alert.source_ip,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "description": alert.description,
        "timestamp": iso_timestamp(alert.timestamp),
        "status": alert.status
    }


def emit_event(event_type, data, **extra):
    """
    Broadcast a WebSocket event without interrupting the caller.
    """

    event = {
        "type": event_type,
        "data": data
    }

    event.update(extra)

    try:
        websocket_manager.broadcast_from_thread(event)

    except Exception:
        pass
