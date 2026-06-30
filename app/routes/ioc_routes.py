from flask import Blueprint
from flask import render_template
from flask import request

from app.ioc.extractor import extract_iocs


ioc_bp = Blueprint(
    "ioc",
    __name__
)


@ioc_bp.route(
    "/ioc",
    methods=["GET", "POST"]
)
def ioc_extractor():

    if request.method == "POST":

        threat_text = request.form.get(
            "threat_text"
        )

        results = extract_iocs(
            threat_text
        )

        return render_template(
            "ioc/result.html",
            results=results,
            threat_text=threat_text
        )

    return render_template(
        "ioc/extractor.html"
    )