"""Authenticated API endpoints for starting and reading Gemini investigations."""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Response
from pydantic import BaseModel

from backend.incident_evidence import (
    IncidentEvidenceDatabaseError,
    get_incident_evidence,
)
from backend.investigation_store import (
    get_investigation,
    retry_investigation,
    update_investigation,
)
from backend.gemini_investigator import (
    GeminiConfigurationError,
    GeminiInvestigationError,
    investigate_incident,
    load_gemini_model,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/incidents", tags=["incident investigations"])


class InvestigationResponse(BaseModel):
    investigation_id: str
    detection_id: int
    status: str
    result: dict[str, Any] | None
    model_id: str
    created_at: str
    completed_at: str | None
    error_code: str | None


def _public_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: record[key]
        for key in (
            "investigation_id",
            "detection_id",
            "status",
            "result",
            "model_id",
            "created_at",
            "completed_at",
            "error_code",
        )
    }


def _run_investigation(investigation_id: str, detection_id: int) -> None:
    update_investigation(investigation_id, status="in_progress")
    try:
        evidence = get_incident_evidence(detection_id)
        if evidence is None:
            raise GeminiInvestigationError("The selected detection no longer exists.")
        report, _ = investigate_incident(evidence)
        update_investigation(
            investigation_id,
            status="completed",
            result=report.model_dump(mode="json"),
        )
    except GeminiConfigurationError:
        update_investigation(
            investigation_id,
            status="failed",
            error_code="investigation_unavailable",
        )
    except GeminiInvestigationError as exc:
        update_investigation(
            investigation_id,
            status="failed",
            error_code=exc.error_code,
        )
    except IncidentEvidenceDatabaseError:
        update_investigation(
            investigation_id,
            status="failed",
            error_code="evidence_unavailable",
        )
    except sqlite3.Error:
        logger.error("Unable to persist Gemini investigation status.")
    except Exception as exc:
        logger.warning(
            "Unexpected investigation failure of type %s.",
            type(exc).__name__,
        )
        try:
            update_investigation(
                investigation_id,
                status="failed",
                error_code="investigation_unavailable",
            )
        except sqlite3.Error:
            logger.error("Unable to persist failed Gemini investigation status.")


@router.post(
    "/{detection_id}/investigate",
    response_model=InvestigationResponse,
    status_code=202,
)
def start_investigation(
    detection_id: int,
    background_tasks: BackgroundTasks,
    response: Response,
) -> dict[str, Any]:
    if detection_id <= 0:
        raise HTTPException(status_code=422, detail="detection_id must be positive.")

    try:
        evidence = get_incident_evidence(detection_id)
    except IncidentEvidenceDatabaseError:
        raise HTTPException(
            status_code=503,
            detail="Incident evidence is temporarily unavailable.",
        ) from None

    if evidence is None:
        raise HTTPException(status_code=404, detail="Detection not found.")
    if evidence["event_reference_status"] != "complete" or not evidence["linked_events"]:
        raise HTTPException(
            status_code=422,
            detail="Complete linked event evidence is required for investigation.",
        )

    try:
        model_id = load_gemini_model()
    except GeminiConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None

    try:
        record, created = retry_investigation(detection_id, model_id)
    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="Investigation storage is temporarily unavailable.",
        ) from None

    if created:
        background_tasks.add_task(
            _run_investigation,
            record["investigation_id"],
            detection_id,
        )
        response.status_code = 202
    else:
        response.status_code = 200
    return _public_record(record)


@router.get(
    "/investigations/{investigation_id}",
    response_model=InvestigationResponse,
)
def read_investigation(
    investigation_id: str,
) -> dict[str, Any]:
    try:
        record = get_investigation(investigation_id)
    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="Investigation storage is temporarily unavailable.",
        ) from None
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return _public_record(record)
