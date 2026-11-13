from fastapi import APIRouter, HTTPException

from app.services.packet_capture import (
    start_capture,
    stop_capture,
    get_capture_status
)


router = APIRouter(
    prefix="/api/capture",
    tags=["Packet Capture"]
)


@router.post("/start")
def start_packet_capture():

    try:
        return start_capture()

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