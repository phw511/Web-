from fastapi import APIRouter, Depends, Response

from webvuln.container import Container
from webvuln.web.deps import get_container, get_current_user

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/reports/{scan_id}")
def report(scan_id: str, format: str = "md",
           user: dict = Depends(get_current_user),
           c: Container = Depends(get_container)):
    media = {"json": "application/json", "md": "text/markdown",
             "html": "text/html; charset=utf-8"}
    body = c.reporter.render(scan_id, format)
    return Response(content=body, media_type=media.get(format, "text/plain"))


@router.get("/stats")
def stats(user: dict = Depends(get_current_user), c: Container = Depends(get_container)):
    by_state = c.db.query(
        "SELECT state, COUNT(*) AS n FROM conclusions GROUP BY state")
    by_vuln = c.db.query(
        "SELECT c.vuln_type, con.state, COUNT(*) AS n FROM conclusions con"
        " JOIN candidates c ON c.id=con.candidate_id GROUP BY c.vuln_type, con.state")
    totals = {r["state"]: r["n"] for r in by_state}
    return {
        "TP": totals.get("CONFIRMED", 0),
        "FP": totals.get("REJECTED", 0),
        "INCONCLUSIVE": totals.get("INCONCLUSIVE", 0),
        "PENDING": c.db.one("SELECT COUNT(*) AS n FROM conclusions"
                            " WHERE state IN ('CANDIDATE','ATTACKED')")["n"],
        "FN": None,  # 需靶场真值集后统计（计划书 5.1）
        "by_vuln_type": by_vuln,
    }
