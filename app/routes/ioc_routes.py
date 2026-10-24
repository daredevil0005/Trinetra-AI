from flask import Blueprint
from flask import render_template
from flask import request

from app.ioc.extractor import extract_iocs
from app.security.auth import login_required


ioc_bp = Blueprint(
    "ioc",
    __name__
)


@ioc_bp.route(
    "/ioc",
    methods=["GET", "POST"]
)
@login_required
def ioc_extractor():
    if request.method == "POST":
        threat_text = request.form.get("threat_text", "")
        if not threat_text.strip():
            return render_template("ioc/extractor.html", error="Paste text to extract indicators from."), 400
        if len(threat_text) > 100_000:
            return render_template("ioc/extractor.html", error="Text must be 100,000 characters or fewer."), 413
        results = extract_iocs(threat_text)
        total = sum(len(values) for values in results.values())
        return render_template("ioc/result.html", results=results, total=total)

    return render_template(
        "ioc/extractor.html"
    )
