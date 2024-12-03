#!/usr/bin/env python3

"""Add CodeQL metadata to Code Scanning alerts.

This can be the abbreviated version of the JSON output supported by the partner script `list_code_scanning_alerts.py`,
or can be the full output from the GitHub API.

The metadata can either be in the format provided by the `codeql resolve metadata` command,
or in the format produced by the script `parse_ql` by the same author as this script.
"""

import json
import argparse
import logging
from html import escape
import re


LOG = logging.getLogger(__name__)

LANGUAGE_LOOKUP = {
    "js": "javascript",
    "py": "python",
    "rb": "ruby"
}


def fix_all_metadata(metadata: dict, metadata_format: str) -> None:
    """Fix up all metadata entries in the dictionary."""
    for rule_id, rule_metadata in metadata.items():
        if metadata_format == "codeql":
            fixup_rule_metadata_codeql(rule_metadata)
        elif metadata_format == "parse_ql":
            fixup_rule_metadata_parse_ql(rule_metadata)
        if "id" in rule_metadata:
            del rule_metadata["id"]
        if "tags" in rule_metadata:
            LOG.debug("Tags: %s", rule_metadata["tags"])
            # pull out main CWE from the tags
            cwe_tags = [tag for tag in rule_metadata["tags"] if tag.startswith("external/cwe/cwe-")]
            if cwe_tags:
                rule_metadata["cwe"] = cwe_tags[0].replace("external/cwe/cwe-", "")


def fixup_rule_metadata_codeql(rule_metadata: dict) -> None:
    """Fix up the rule metadata to make it more usable."""

    # tags are output as a single string, but we want them as a list
    if "tags" in rule_metadata:
        rule_metadata["tags"] = rule_metadata["tags"].split(" ")

    if "security-severity" in rule_metadata:
        try:
            rule_metadata["security-severity"] = float(rule_metadata["security-severity"])
        except:
            LOG.warning(
                "Could not parse security-severity in rule %s as float: %s",
                rule_metadata.get("id", "unknown ID"),
                rule_metadata["security-severity"]
            )
    
    # add language by parsing the rule ID
    language_from_id = rule_metadata["id"].split("/")[0]
    rule_metadata["language"] = LANGUAGE_LOOKUP.get(language_from_id, language_from_id)


def fixup_rule_metadata_parse_ql(rule_metadata: dict) -> None:
    """Fix up the rule metadata to make it more usable."""

    # this is just used to correlate the QHelp files with the .ql files, we don't need to retain it
    if "filename" in rule_metadata:
        del rule_metadata["filename"]


def enrich_alerts(alerts: list, metadata: dict) -> None:
    """Enrich the alerts with the rule metadata."""
    for alert in alerts:
        if alert["tool_name"] == "CodeQL":
            LOG.debug("Adding metadata")
            rule_id = alert["rule_id"]
            LOG.debug("Rule ID: %s", rule_id)
            rule_metadata = metadata.get(rule_id, {})

            if not rule_metadata:
                LOG.warning("No metadata found for rule ID %s", rule_id)
                LOG.debug("All metadata keys: %s", metadata.keys())
            LOG.debug("Metadata: %s", rule_metadata)
            alert.update(rule_metadata)


PUNCTUATION_RE = re.compile(r"[._-]")


def format_headings(keys: list[str]) -> str:
    """Format the headings of the table."""
    cells = []
    for key in keys:
        cells.append("<th>{}</th>".format(
            escape(
                PUNCTUATION_RE.sub(" ", key).title() if key not in ["cwe"] else key.upper()
            )
        ))
    return "<thead>{}</thead>".format("".join(cells))


def format_row(alert: dict, keys: list) -> str:
    """Format a single row of the table."""
    cells = []
    for key in keys:
        value = alert.get(key)
        if value is None:
            value = "-"
        cells.append("<td>{}</td>".format(
            format_value(key, value)
        ))
    return "<tr>{}</tr>".format("".join(cells))


FA_TITLES = {
    "javascript": "js",
    "go": "golang",
}


def format_value(key: str, value: float|str) -> str:
    """Format a value for a cell in the table, depending on the key."""
    if value == "-":
        return str(value)

    if key == "security-severity":
        try:
            value = float(value)
        except (TypeError, ValueError):
            return escape(str(value))
        label: str = "none"
        # colour/symbol based on CVSS ranges
        if value >= 9.0:
            label = "critical"
        elif value >= 7.0:
            label = "high"
        elif value >= 4.0:
            label = "medium"
        elif value >= 0.1:
            label = "low"
        return '<span title="{}" class="badge bg-{} rounded-pill">{}</span>'.format(
            escape(str(value), quote=True),
            "info" if label == "none" else "success" if label == "low" else "warning" if label == "medium" else "danger",
            escape(label)
        )
    elif key == "state":
        return '<span class="badge bg-{} rounded-pill">{}</span>'.format(
            "success" if value == "fixed" else "secondary" if value == "dismissed" else "danger",
            escape(str(value))
        )
    elif key == "precision":
        return '<span class="badge bg-{} rounded-pill">{}</span>'.format(
            "success" if value == "high" else "warning" if value == "medium" else "danger",
            escape(str(value))
        )
    elif key == "rule_severity":
        return '<span class="badge bg-{} rounded-pill">{}</span>'.format(
            "warning" if value == "warning" else "danger" if value == "error" else "primary",
            escape(str(value))
        )
    elif key == "language":
        if value in ["python", "javascript", "java", "go", "swift"]:
            fa_title = FA_TITLES.get(str(value), value)
            return '<i class="fab fa-{}" title="{}"></i>'.format(escape(str(fa_title), quote=True), escape(str(value)))
        return '<span class="badge bg-primary rounded-pill">{}</span>'.format(
            escape(str(value))
        )
    elif key == "ref":
        # strip off 'refs/heads/' prefix, if there
        ref = escape(str(value)[len("refs/heads/"):] if str(value).startswith("refs/heads/") else str(value))
        return '<span class="badge bg-primary rounded-pill">{}</span>'.format(ref)
    elif key == "rule_id":
        return '<span style="font-size: small;">{}</span>'.format(escape(str(value)))
    else:
        return escape(str(value))


def html_output(alerts: list, stylesheet_path: str|None=None) -> str:
    """Generate a simple HTML representation of the alerts, in a table. Use HTML escaping."""
    fields = ["created_at", "repo", "language", "ref", "path", "state", "rule_id", "tool_name", "cwe", "rule_description", "rule_severity", "security-severity", "precision"]

    heading = format_headings(fields)

    rows = []
    for alert in alerts:
        rows.append(format_row(alert, fields))

    table = '<table id="alerts" class="table table-striped table-hover">\n{}\n{}</table>'.format(heading, "\n".join(rows))

    stylesheets = """
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous" />
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.5/css/dataTables.bootstrap5.min.css" integrity="sha384-5oFfLntNy8kuC2TaebWZbaHTqdh3Q+7PwYbB490gupK0YtTAB7mBJGv4bQl9g9rK" crossorigin="anonymous" />
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.1/css/all.min.css" integrity="sha512-5Hs3dF2AEPkpNAR7UiOHba+lRSJNeM2ECkwxUIxC1Q/FLycGTbNapWXB4tP889k5T5Ju8fs4b1P5z/iB4nMfSQ==" crossorigin="anonymous" />
"""
    
    scripts = """
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<script src="https://code.jquery.com/jquery-3.7.0.js" integrity="sha384-ogycHROOTGA//2Q8YUfjz1Sr7xMOJTUmY2ucsPVuXAg4CtpgQJQzGZsX768KqetU" crossorigin="anonymous"></script>
<script src="https://cdn.datatables.net/1.13.5/js/jquery.dataTables.min.js" integrity="sha384-8YRuqcmsgzJVFNG6QuO77MAyein6qrWXIY/kkAnn/R8wksSCqhCkWNELjDllpffy" crossorigin="anonymous"></script>
<script src="https://cdn.datatables.net/responsive/2.1.0/js/dataTables.responsive.min.js" integrity="sha384-VPEdSQrwo2+kA/WW4V5bP9Vyi1UamWp5zcxop+N1gQgZj2en3sR7efLLjU0PDgmU" crossorigin="anonymous"></script>
<script src="https://cdn.datatables.net/1.13.5/js/dataTables.bootstrap5.min.js" integrity="sha384-dgTxndj+aTqKfEhg2Q5EVhy+lf8oMgZLYOgl5p7B71gTNhAjWRX+CGwXJh9Q5SBV" crossorigin="anonymous"></script>
"""

    jquery_document_ready = """
<script type="text/javascript">
$(document).ready(function() {
    $('#alerts').DataTable({
      language: {
        //customize pagination prev and next buttons: use arrows instead of words
        'paginate': {
          'previous': '<span class="fas fa-chevron-left"></span>',
          'next': '<span class="fas fa-chevron-right"></span>'
        },
        //customize number of elements to be displayed
        "lengthMenu": 'Display <select class="form-control input-sm">'+
        '<option value="10">10</option>'+
        '<option value="20">20</option>'+
        '<option value="40">40</option>'+
        '<option value="80">80</option>'+
        '<option value="-1">All</option>'+
        '</select> results'
      }
    })  
} );
</script>
"""

    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Code Scanning results</title>
{}
</head>
<body>
{}
{}
{}
</body>
</html>""".format(stylesheets, scripts, jquery_document_ready, table)

    return html

def add_args(parser: argparse.ArgumentParser) -> None:
    """Add command-line arguments to the parser."""
    parser.add_argument(
        "alerts",
        type=argparse.FileType("r"),
        help="JSON file containing the alerts to enrich",
    )
    parser.add_argument(
        "metadata",
        type=argparse.FileType("r"),
        help="JSON file containing the metadata to add to the alerts, which must be indexed by the rule ID",
    )
    parser.add_argument(
        "--metadata-format",
        "-m",
        choices=["codeql", "parse_ql"],
        default="codeql",
        help="Format of the metadata",
    )
    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Print debug information",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "html"],
    )
    parser.add_argument(
        "--stylesheet",
        "-s",
        required=False,
        help="Path to a CSS file for styling the HTML output (defaults to Bootstrap via JSdelivr CDN with integrity hash)",
    )


def main() -> None:
    """Command-line entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    alerts = json.load(args.alerts)
    metadata = json.load(args.metadata)

    fix_all_metadata(metadata, args.metadata_format)
    enrich_alerts(alerts, metadata)

    if args.format == "json":
        print(json.dumps(alerts, indent=2))
    elif args.format == "html":
        print(html_output(alerts, args.stylesheet))


if __name__ == "__main__":
    main()
