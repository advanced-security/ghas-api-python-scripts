#!/usr/bin/env python3

"""Add CodeQL metadata to Code Scanning alerts and produce output.

This must be the abbreviated version of the JSON output supported by the partner script `list_code_scanning_alerts.py`.

The metadata can either be in the format provided by the `codeql resolve metadata` command,
or in the format produced by the script `parse_ql` by the same author as this script.
"""

import json
import argparse
import logging
from html import escape
import re
from typing import Any
from pathlib import Path
from datetime import datetime
import time
from mistletoe import markdown
import humanize
from defusedcsv import csv


LOG = logging.getLogger(__name__)

LANGUAGE_LOOKUP = {"js": "javascript", "py": "python", "rb": "ruby"}


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
            # pull out main CWE from the tags
            cwe_tags = [
                tag
                for tag in rule_metadata["tags"]
                if tag.startswith("external/cwe/cwe-")
            ]
            if cwe_tags:
                rule_metadata["cwe"] = cwe_tags[0].replace("external/cwe/cwe-", "")


def fixup_rule_metadata_codeql(rule_metadata: dict) -> None:
    """Fix up the rule metadata to make it more usable."""

    # tags are output as a single string, but we want them as a list
    if "tags" in rule_metadata:
        rule_metadata["tags"] = rule_metadata["tags"].split(" ")

    if "security-severity" in rule_metadata:
        try:
            rule_metadata["security-severity"] = float(
                rule_metadata["security-severity"]
            )
        except:
            LOG.warning(
                "Could not parse security-severity in rule %s as float: %s",
                rule_metadata.get("id", "unknown ID"),
                rule_metadata["security-severity"],
            )

    # add language by parsing the rule ID
    language_from_id = rule_metadata["id"].split("/")[0]
    rule_metadata["language"] = LANGUAGE_LOOKUP.get(language_from_id, language_from_id)


def fixup_rule_metadata_parse_ql(rule_metadata: dict) -> None:
    """Fix up the rule metadata to make it more usable."""

    # this is just used to correlate the QHelp files with the .ql files, we don't need to retain it
    if "filename" in rule_metadata:
        del rule_metadata["filename"]


def fixup_alerts(alerts: list[dict]) -> None:
    """Add a formatted code location."""
    for alert in alerts:
        if alert["start_line"] == alert["end_line"]:
            location = "{}:{}-{}".format(
                alert["start_line"], alert["start_column"], alert["end_column"]
            )
        else:
            location = "{}:{}-{}:{}".format(
                alert["start_line"],
                alert["start_column"],
                alert["end_line"],
                alert["end_column"],
            )
        alert["location"] = location

        # if there's no language, try to infer one from the file extension
        if "language" not in alert:
            if "path" in alert:
                parts = alert["path"].split(".")
                if len(parts) > 1:
                    alert["language"] = LANGUAGE_LOOKUP.get(parts[-1], parts[-1])

        # if there's no security-severity, and one of 0.0
        if "security-severity" not in alert:
            alert["security-severity"] = 0.0


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


def format_header(key: str) -> str:
    """Format the heading depending on its value."""
    if key not in ["cwe", "language"]:
        output = PUNCTUATION_RE.sub(" ", key).title()
    elif key == "cwe":
        output = key.upper()
    elif key == "language":
        output = "Lang"
    return output


def format_headings(keys: list[str], noprint_keys: list[str]|None = None) -> str:
    """Format the headings of the table."""
    cells = []
    for key in keys:
        cells.append(
            "<th{}>{}</th>".format(
                ' class="no-print"' if noprint_keys is not None and key in noprint_keys else "",
                escape(format_header(key)),
            )
        )
    return "<thead>{}</thead>".format("".join(cells))


def format_row(alert: dict, keys: list, cwe_dict: dict[str, str] | None = None, noprint_keys: list[str]|None = None) -> str:
    """Format a single row of the table."""
    cells = []
    for key in keys:
        value = alert.get(key)
        if value is None:
            value = "-"
        cells.append(
            "<td{}>{}</td>".format(
                ' class="no-print"' if noprint_keys is not None and key in noprint_keys else "",
                format_value(key, value, alert, cwe_dict),
            )
        )
    return "<tr>{}</tr>".format("".join(cells))


FA_TITLES = {
    "javascript": "js",
    "go": "golang",
}

CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0
CVSS_LOW = 0.1


def format_value(
    key: str, value: Any, data: dict[str, Any], cwe_dict: dict[str, str] | None = None
) -> str:
    """Format a value for a cell in the table, depending on the key."""
    if value == "-":
        return str(value)

    if key == "cwe":
        cwe_value = str(value).lstrip("0")
        return '<a href="https://cwe.mitre.org/data/definitions/{}.html" title="{}">{}</a>'.format(
            escape(cwe_value, quote=True),
            (
                escape(cwe_dict.get(cwe_value, cwe_value), quote=True)
                if cwe_dict is not None
                else escape(cwe_value, quote=True)
            ),
            escape(cwe_value),
        )
    if key == "security-severity":
        try:
            value = float(value)
        except (TypeError, ValueError):
            return escape(str(value))
        label: str = "none"
        # colour/symbol based on CVSS ranges
        if value >= CVSS_CRITICAL:
            label = "critical"
        elif value >= CVSS_HIGH:
            label = "high"
        elif value >= CVSS_MEDIUM:
            label = "medium"
        elif value >= CVSS_LOW:
            label = "low"
        return '<span title="{}" class="badge bg-{} rounded-pill">{}</span>'.format(
            escape(str(value), quote=True),
            (
                "info"
                if label == "none"
                else (
                    "success"
                    if label == "low"
                    else "warning" if label == "medium" else "danger"
                )
            ),
            escape(label),
        )
    elif key == "state":
        return '<span class="badge bg-{} rounded-pill">{}</span>'.format(
            (
                "success"
                if value == "fixed"
                else "secondary" if value == "dismissed" else "danger"
            ),
            escape(str(value)),
        )
    elif key == "precision":
        return '<span class="badge bg-{} rounded-pill">{}</span>'.format(
            (
                "success"
                if value == "high"
                else "warning" if value == "medium" else "danger"
            ),
            escape(str(value)),
        )
    elif key == "rule_severity":
        return '<span class="badge bg-{} rounded-pill">{}</span>'.format(
            (
                "warning"
                if value == "warning"
                else "danger" if value == "error" else "primary"
            ),
            escape(str(value)),
        )
    elif key == "language":
        if value in ["python", "javascript", "java", "go", "swift"]:
            fa_title = FA_TITLES.get(str(value), value)
            return '<i class="fab fa-{}" title="{}"></i><span style="display:none;">{}</span>'.format(
                escape(str(fa_title), quote=True),
                escape(str(value)),
                escape(str(value)),
            )
        return '<span class="badge bg-primary rounded-pill">{}</span>'.format(
            escape(str(value))
        )
    elif key == "ref":
        # strip off 'refs/heads/' prefix, if there
        # add the exact commit as a tooltip
        ref = (
            str(value)[len("refs/heads/") :]
            if str(value).startswith("refs/heads/")
            else str(value)
        )
        return (
            '<span class="badge bg-primary rounded-pill" title="{}">{}</span>'.format(
                escape(data.get("commit_sha", "-")), escape(ref)
            )
        )
    elif key == "rule_id":
        return '<span style="font-size: small;" title="{}">{}</span>'.format(
            escape(
                data["rule_description"] if "rule_description" in data else str(value),
                quote=True,
            ),
            escape(str(value)),
        )
    elif key == "rule_help":
        if value == "":
            return "-"
        # turn Markdown into HTML, inline under a details element
        return '<details><summary>+</summary>{}</details>'.format(
            # markdown to HTML with a library
            markdown(value)
        )
    elif key == "url":
        return '<a title="Open the alert on GitHub Advanced Security" href="{}"><i class="fa-solid fa-link code-scanning-url"></i></a>'.format(
            escape(str(value), quote=True)
        )
    elif key == "created_at":
        natural_date = humanize.naturaltime(datetime.fromisoformat(str(value)))
        return '<span style="display:none">{}</span><span title="{}">{}</span>'.format(
            escape(str(value)), escape(str(value)), escape(natural_date)
        )
    else:
        return escape(str(value))


def make_summary(
    alerts: list[dict],
    scope: str,
    cwe_counts: dict[str, int],
    cwe_dict: dict[str, str] | None,
) -> str:
    """Make an HTML summary of the alerts."""
    title = '<div><h1><i class="fa-brands fa-github" style="font-size: xxx-large" title="GitHub Advanced Security"></i> Code Scanning Report</h1></div>'
    generated_at = '<div style="font-size: small">Generated at {}Z</div>'.format(
        datetime.utcnow().isoformat(timespec="seconds")
    )
    scope = "<div><strong>Scope</strong>: {}</div>".format(escape(scope))

    summary = "<div><strong>Total</strong>: {} alerts</div>".format(len(alerts))

    severity = '<div style="width:33%; float:left; "><table class="table"><tr><td style="width:50%; background-color: #FFDDDD;">CRITICAL<br />{}</td><td style="width:50%; background-color: #FFEEDD;">HIGH<br />{}</td></tr><tr><td style="width:50%; background-color: #FFFFDD;">MEDIUM<br />{}</td><td style="width:50%; background-color: #DDDDDD;">LOW<br />{}</td></tr></table></div>'.format(
        len(
            [
                a
                for a in alerts
                if isinstance(a["security-severity"], float)
                and a["security-severity"] >= CVSS_CRITICAL
            ]
        ),
        len(
            [
                a
                for a in alerts
                if isinstance(a["security-severity"], float)
                and a["security-severity"] >= CVSS_HIGH
                and a["security-severity"] < CVSS_CRITICAL
            ]
        ),
        len(
            [
                a
                for a in alerts
                if isinstance(a["security-severity"], float)
                and a["security-severity"] >= CVSS_MEDIUM
                and a["security-severity"] < CVSS_HIGH
            ]
        ),
        len(
            [
                a
                for a in alerts
                if isinstance(a["security-severity"], float)
                and a["security-severity"] < CVSS_MEDIUM
                or a["security-severity"] is None
            ]
        ),
    )

    cwe_summary = (
        '<div style="width:33%; float:left; "><strong>Top 5 CWEs</strong>:<ol>'
    )

    for cwe, count in sorted(
        cwe_counts.items(), key=lambda item: item[1], reverse=True
    )[:5]:
        cwe_name = cwe_dict.get(cwe.lstrip("0"), cwe) if cwe_dict is not None else cwe
        if cwe == "other":
            cwe_summary += "<li>Other: {}</li>".format(count)
        else:
            cwe_summary += '<li title="{}">CWE-{} ({}): {}</li>'.format(
                cwe_name, cwe.lstrip("0"), cwe_name, count
            )
    cwe_summary += "</ol></div>"

    cwe_canvas = '<div style="float: left;"><canvas id="myChart"></canvas></div>'

    return (
        title
        + generated_at
        + scope
        + summary
        + severity
        + cwe_summary
        + cwe_canvas
        + '<div style="clear:both;"></div>'
    )


def html_output(
    alerts: list[dict],
    fields: list[str],
    scope: str,
    groupby: str | None = None,
    cwe_dict: dict[str, str] | None = None,
) -> str:
    """Generate a simple HTML representation of the alerts, in a table. Use HTML escaping."""

    cwe_counts: dict[str, int] = {}
    for alert in alerts:
        cwe = alert.get("cwe")
        if cwe is not None:
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

    # just keep the top 5 CWEs
    cwe_counts_top = {
        k: v
        for k, v in sorted(cwe_counts.items(), key=lambda item: item[1], reverse=True)[
            0:5
        ]
    }
    cwe_counts_top["other"] = sum(cwe_counts.values()) - sum(cwe_counts_top.values())

    LOG.debug(cwe_counts_top)

    summary = make_summary(alerts, scope, cwe_counts_top, cwe_dict)

    noprint_keys = ["rule_help", "url"]

    heading = format_headings(fields, noprint_keys=noprint_keys)

    content: str = ""

    # group by the selected field
    # check if it is one of the displayed fields, first
    if groupby is not None and groupby not in fields:
        LOG.warning("Cannot group by field %s, not in output", groupby)
        groupby = None

    if groupby is not None:
        # group the alerts by that field, in a dict
        groups: dict[str, list[dict]] = {}

        for alert in alerts:
            try:
                key = alert[groupby]
            except KeyError:
                key = "-"
            groups[key] = [] if groups.get(key) is None else groups[key]
            groups[key].append(alert)

        # generate a table for each group, and put it inside a table of all of the groups
        tables = {}

        for key, group_alerts in groups.items():
            group_table = '<table id="{}_alerts" class="table table-striped table-hover">\n{}\n{}</table>'.format(
                escape(key, quote=True),
                heading,
                "\n".join(
                    [format_row(alert, fields, cwe_dict, noprint_keys=noprint_keys) for alert in group_alerts]
                ),
            )
            tables[key] = group_table

        content = '<table id="groups" class="table table-striped table-hover">\n<thead><th style="width:5%">{}</th><th>Alerts</th></thead>\n{}'.format(
            escape(format_header(groupby), quote=True),
            "\n".join(
                [
                    '<tr><td style="width:5%">{}: {}</td><td>{}</td></tr>'.format(
                        format_value(groupby, key, {}, cwe_dict),
                        len(groups[key]),
                        '<details class="rule-help"><summary>+</summary>{}</details>'.format(
                            tables[key]
                        ),
                    )
                    for key in sorted(tables.keys())
                ]
            ),
        )

    else:
        table = '<table id="alerts" class="table table-striped table-hover" data-page-length="-1">\n{}\n{}</table>'.format(
            heading,
            "\n".join([format_row(alert, fields, cwe_dict, noprint_keys=noprint_keys) for alert in alerts]),
        )

        content = table

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
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js" integrity="sha512-ZwR1/gSZM3ai6vCdI+LVF1zSq/5HznD3ZSTk7kajkaj4D292NLuduDCO1c/NT8Id+jE58KYLKT7hXnbtryGmMg==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
"""

    cwe_labels: str = ",".join(
        ["'{}'".format(cwe.lstrip("0")) for cwe in cwe_counts_top.keys()]
    )
    cwe_values: str = ",".join(
        ["{}".format(count) for count in cwe_counts_top.values()]
    )

    jquery_document_ready = """
<script type="text/javascript">
$(document).ready(function() {{
    // DataTable
    let table = $('#alerts').DataTable({{
      language: {{
        //customize pagination prev and next buttons: use arrows instead of words
        'paginate': {{
          'previous': '<span class="fas fa-chevron-left"></span>',
          'next': '<span class="fas fa-chevron-right"></span>'
        }},
        //customize number of elements to be displayed
        "lengthMenu": 'Display <select class="form-control input-sm">'+
        '<option value="10">10</option>'+
        '<option value="20">20</option>'+
        '<option value="40">40</option>'+
        '<option value="80">80</option>'+
        '<option value="-1">All</option>'+
        '</select> results'
      }}
    }});

    const data = {{
        labels: [{}],
        datasets: [{{
            label: 'Top 5 CWEs',
            data: [{}],
            backgroundColor: [
            'rgb(255, 99, 132)',
            'rgb(54, 162, 235)',
            'rgb(255, 205, 86)',
            'rgb(75, 192, 192)',
            'rgb(153, 102, 255)',
            'rgb(255, 159, 64)'
            ],
            hoverOffset: 4,
        }}]
    }};

    const config = {{
        type: 'doughnut',
        data: data,
        options: {{
            animation: false
        }}
    }};

    const ctx = document.getElementById('myChart');

    new Chart(ctx, config);
}} );
</script>
""".format(
        cwe_labels, cwe_values
    )

    hide_print_style = """
<style>
@media print {
  .dataTables_filter, .dataTables_length, .dataTables_paginate, .code-scanning-url, .no-print {
    display: none;
  }
}
</style>
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
{}
{}
</body>
</html>""".format(
        stylesheets,
        scripts,
        hide_print_style,
        jquery_document_ready if groupby is None else "",
        summary,
        content,
    )

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
        "scope",
        help="Target of the report - e.g. the org, repo or Enterprise name being scanned",
    )
    parser.add_argument(
        "--mitre-cwe-csv",
        type=argparse.FileType("r"),
        help="CSV file containing MITRE CWE data for Software Development from https://cwe.mitre.org/data/csv/699.csv.zip",
    )
    parser.add_argument(
        "--metadata-format",
        "-m",
        choices=["codeql", "parse_ql"],
        default="parse_ql",
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
        default="json",
        choices=["json", "html", "pdf"],
        help="Output format",
    )
    parser.add_argument(
        "--fields",
        "-F",
        required=False,
        help="Comma-separated list of fields to include in the output",
    )
    parser.add_argument(
        "--groupby",
        "-g",
        required=False,
        help="Field to group the alerts by",
    )


def main() -> None:
    """Command-line entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    alerts = json.load(args.alerts)
    metadata = json.load(args.metadata)
    cwe_data = csv.reader(args.mitre_cwe_csv) if args.mitre_cwe_csv else None

    cwe_dict: dict[str, str] = {}

    if cwe_data is not None:
        for row in cwe_data:
            cwe_dict[row[0]] = row[1]

    fix_all_metadata(metadata, args.metadata_format)
    enrich_alerts(alerts, metadata)
    fixup_alerts(alerts)

    if args.format in ["html", "pdf"]:
        fields = (
            [
                "created_at",
                "url",
                "repo",
                "language",
                # "ref",
                "path",
                "location",
                "state",
                # "rule_id",
                # "tool_name",
                "cwe",
                "message",
                "rule_severity",
                "security-severity",
                "precision",
                "rule_help",
            ]
            if args.fields is None
            else args.fields.split(",")
        )

    if args.format == "json":
        print(json.dumps(alerts, indent=2))
    elif args.format == "html":
        print(html_output(alerts, fields, args.scope, args.groupby, cwe_dict))
    elif args.format == "pdf":
        html_content = html_output(alerts, fields, args.scope, args.groupby, cwe_dict)
        with open("report.html", "w") as out:
            out.write(html_content)

        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            path = Path("./report.html").absolute().as_uri()
            page.goto(path)
            page.pdf(path="report.pdf", scale=0.75, format="A4", print_background=True)


if __name__ == "__main__":
    main()
