from fastapi import APIRouter, HTTPException

from app.services.packet_capture import (
    CAPTURE_SUPPORTED,
    CAPTURE_UNSUPPORTED_MESSAGE,
    CaptureUnsupportedError,
    start_capture,
    stop_capture,
    get_capture_status,
    get_available_interfaces
)


router = APIRouter(
    prefix="/api/capture",
    tags=["Packet Capture"]
)


@router.post("/start")
def start_packet_capture(payload: dict | None = None):

    interface = payload.get("interface") if payload else None

    try:
        return start_capture(interface)

    except CaptureUnsupportedError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error)
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


@router.post("/stop")
def stop_packet_capture():

    try:
        return stop_capture()

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


@router.get("/status")
def packet_capture_status():

    return get_capture_status()


@router.get("/interfaces")
def available_interfaces():

    return {
        "interfaces": get_available_interfaces(),
        "supported": CAPTURE_SUPPORTED,
        "reason": None if CAPTURE_SUPPORTED else CAPTURE_UNSUPPORTED_MESSAGE
    }