"""Route implementation for executing AI agent runs on privacy sessions."""

from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException, status
from app.agent_gateway import agent_gateway
from app.audit_log import audit_logger
from app.receipts import receipt_issuer
from app.schemas import SessionRunRequest, SessionRunResponse
from app.session_manager import session_manager

router = APIRouter(prefix="/v1", tags=["Execution"])


@router.post(
    "/sessions/{session_id}/run",
    response_model=SessionRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute AI Task on Session Image",
    description=(
        "Executes an AI task against the in-memory image buffer, subject to strict egress firewall "
        "filtering, allowlisted tool enforcement, and mandatory memory zeroing upon completion."
    ),
)
async def run_session(
    session_id: str,
    request: SessionRunRequest,
) -> SessionRunResponse:
    """Execute AI task following strict sequential privacy guarantees.

    Flow:
    1. Look up session; 404 if missing or expired.
    2. Pass task text through EgressFirewall. Block if flagged (403).
    3. Inside `with session.buffer:` call the model (Gemini or OpenAI).
    4. Pass model response and tool calls through EgressFirewall before execution/return.
    5. In `finally:` ALWAYS wipe buffer, remove session, generate deletion receipt, and log audit events.
    6. Return firewalled answer plus session_id and receipt_id.
    """
    # 1. Look up session
    session = session_manager.get_session(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or expired.",
        )

    task_text: str = request.task_override if request.task_override is not None else session.task
    image_sha256: str = session.image_sha256

    run_status: str = "run_blocked"
    receipt_data: Dict[str, Any] = {}
    answer_text: str = ""
    executed_tool_calls: List[Dict[str, Any]] = []

    # Audit log: run_started
    audit_logger.log_event(
        event_type="run_started",
        session_id=session_id,
        image_sha256=image_sha256,
        metadata={"provider": request.provider},
    )

    try:
        # 2. Inspect input task text through EgressFirewall
        task_decision = agent_gateway.firewall.inspect_input_text(
            text=task_text,
            session_id=session_id,
            image_sha256=image_sha256,
        )
        if not task_decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Firewall blocked task: {task_decision.rule_id} - {task_decision.reason}",
            )

        # 3. Inside `with session.buffer:` call the model
        with session.buffer:
            raw_answer, requested_tools = await agent_gateway._dispatch_to_model(
                provider=request.provider,
                task=task_text,
                buffer=session.buffer,
                session_id=session_id,
            )

            # 4. Pass every tool call through EgressFirewall before execution
            for tool_call in requested_tools:
                t_name = tool_call.get("name", "")
                t_args = tool_call.get("args", {})
                t_decision = agent_gateway.firewall.inspect_tool_call(
                    tool_name=t_name,
                    tool_args=t_args,
                    session_id=session_id,
                    image_sha256=image_sha256,
                )
                if not t_decision.allowed:
                    # Abort run, do NOT execute tool
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Firewall blocked tool call: {t_decision.rule_id} - {t_decision.reason}",
                    )

                # Tool allowed: execute safe allowlisted tool
                tool_res = await agent_gateway.execute_tool(t_name, t_args)
                executed_tool_calls.append(
                    {"name": t_name, "args": t_args, "result": tool_res}
                )

            # Pass model response through EgressFirewall before returning
            out_decision = agent_gateway.firewall.inspect_model_output(
                output_text=raw_answer,
                session_id=session_id,
                image_sha256=image_sha256,
            )
            if not out_decision.allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Firewall blocked model output: {out_decision.rule_id} - {out_decision.reason}",
                )

            answer_text = (
                out_decision.redacted_output
                if out_decision.redacted_output is not None
                else raw_answer
            )
            run_status = "run_finished"

    finally:
        # 5. In a `finally:` block ALWAYS:
        # a) wipe the buffer
        session.buffer.wipe()
        # b) remove session from memory
        session_manager.remove_session(session_id)
        # c) generate deletion receipt
        receipt_data = receipt_issuer.issue_receipt(
            session_id=session_id,
            image_sha256=image_sha256,
            bytes_wiped=session.buffer.bytes_wiped,
            wipe_verified=session.buffer.wipe_verified,
        )
        # d) write audit events: run_finished/run_blocked and image_wiped
        audit_logger.log_event(
            event_type=run_status,
            session_id=session_id,
            image_sha256=image_sha256,
            metadata={"status": run_status},
        )
        audit_logger.log_event(
            event_type="image_wiped",
            session_id=session_id,
            image_sha256=image_sha256,
            metadata={
                "bytes_wiped": session.buffer.bytes_wiped,
                "wipe_verified": session.buffer.wipe_verified,
                "receipt_id": receipt_data.get("receipt_id", ""),
            },
        )

    # 6. Return model's (firewalled) answer plus session_id and receipt_id
    return SessionRunResponse(
        session_id=session_id,
        receipt_id=receipt_data.get("receipt_id", ""),
        answer=answer_text,
        tool_calls=executed_tool_calls,
    )
