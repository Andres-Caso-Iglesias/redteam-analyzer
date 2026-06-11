"""HTML templates for report generation.

Uses Jinja2 syntax for template rendering.
"""

DEFAULT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Red Team Report — {{ target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        header { background: #161b22; border-bottom: 1px solid #30363d; padding: 2rem 0; margin-bottom: 2rem; }
        h1 { color: #f0f6fc; font-size: 2rem; }
        h2 { color: #58a6ff; margin: 2rem 0 1rem; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }
        h3 { color: #c9d1d9; margin: 1rem 0 0.5rem; }
        .summary { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1.5rem; margin-bottom: 2rem; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
        .summary-item { text-align: center; }
        .summary-value { font-size: 2rem; font-weight: bold; }
        .summary-label { color: #8b949e; font-size: 0.9rem; }
        .critical { color: #f85149; }
        .high { color: #db6d28; }
        .medium { color: #d29922; }
        .low { color: #58a6ff; }
        .info { color: #8b949e; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #30363d; }
        th { background: #161b22; color: #f0f6fc; font-weight: 600; }
        tr:hover { background: #161b22; }
        .severity-badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; }
        .severity-critical { background: #f85149; color: white; }
        .severity-high { background: #db6d28; color: white; }
        .severity-medium { background: #d29922; color: white; }
        .severity-low { background: #58a6ff; color: white; }
        .severity-info { background: #8b949e; color: white; }
        .finding { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; margin: 0.5rem 0; }
        .finding-title { font-weight: 600; margin-bottom: 0.5rem; }
        .finding-meta { color: #8b949e; font-size: 0.85rem; }
        pre { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; overflow-x: auto; font-size: 0.9rem; }
        code { font-family: 'SF Mono', 'Fira Code', monospace; }
        footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #30363d; color: #8b949e; text-align: center; font-size: 0.85rem; }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🔍 Red Team Analysis Report</h1>
            <p style="color: #8b949e; margin-top: 0.5rem;">Target: {{ target }} | Generated: {{ timestamp }}</p>
        </div>
    </header>

    <div class="container">
        <!-- Summary -->
        <div class="summary">
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-value">{{ total_findings }}</div>
                    <div class="summary-label">Total Findings</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value critical">{{ critical_count }}</div>
                    <div class="summary-label">Critical</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value high">{{ high_count }}</div>
                    <div class="summary-label">High</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value medium">{{ medium_count }}</div>
                    <div class="summary-label">Medium</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value low">{{ low_count }}</div>
                    <div class="summary-label">Low</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value info">{{ info_count }}</div>
                    <div class="summary-label">Info</div>
                </div>
            </div>
        </div>

        <!-- Findings by Severity -->
        {% for severity in ['critical', 'high', 'medium', 'low', 'info'] %}
        {% set severity_findings = findings | selectattr('severity.value', 'equalto', severity) | list %}
        {% if severity_findings %}
        <h2>{{ severity | upper }} ({{ severity_findings | length }})</h2>
        {% for finding in severity_findings %}
        <div class="finding">
            <div class="finding-title">
                <span class="severity-badge severity-{{ severity }}">{{ severity }}</span>
                {{ finding.title }}
            </div>
            <div class="finding-meta">
                📍 {{ finding.location }} | 📁 {{ finding.type.value }}
                {% if finding.cve_id %} | 🔖 {{ finding.cve_id }}{% endif %}
                {% if finding.cvss_score %} | CVSS: {{ finding.cvss_score }}{% endif %}
            </div>
            {% if finding.description %}
            <p style="margin-top: 0.5rem;">{{ finding.description }}</p>
            {% endif %}
            {% if finding.remediation %}
            <p style="margin-top: 0.5rem; color: #58a6ff;"><strong>Remediation:</strong> {{ finding.remediation }}</p>
            {% endif %}
        </div>
        {% endfor %}
        {% endif %}
        {% endfor %}

        <!-- Metadata -->
        <h2>Scan Metadata</h2>
        <table>
            <thead>
                <tr><th>Plugin</th><th>Duration</th><th>Timestamp</th></tr>
            </thead>
            <tbody>
                {% for meta in metadata %}
                <tr>
                    <td>{{ meta.plugin_name }}</td>
                    <td>{{ meta.duration_seconds }}s</td>
                    <td>{{ meta.timestamp }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        {% if errors %}
        <h2>Errors</h2>
        <table>
            <thead>
                <tr><th>Error</th></tr>
            </thead>
            <tbody>
                {% for error in errors %}
                <tr><td style="color: #f85149;">{{ error }}</td></tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
    </div>

    <footer>
        <p>Generated by redteam-analyzer v{{ version }} | {{ timestamp }}</p>
    </footer>
</body>
</html>"""

EXECUTIVE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Summary — {{ target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #ffffff; color: #1f2328; line-height: 1.6; }
        .container { max-width: 900px; margin: 0 auto; padding: 2rem; }
        header { background: #f6f8fa; border-bottom: 1px solid #d0d7de; padding: 2rem 0; margin-bottom: 2rem; }
        h1 { color: #1f2328; font-size: 1.8rem; }
        h2 { color: #1f2328; margin: 2rem 0 1rem; border-bottom: 1px solid #d0d7de; padding-bottom: 0.5rem; }
        .summary { background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; padding: 1.5rem; margin-bottom: 2rem; }
        .risk-high { color: #cf222e; font-weight: bold; }
        .risk-medium { color: #9a6700; font-weight: bold; }
        .risk-low { color: #0969da; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #d0d7de; }
        th { background: #f6f8fa; }
        .badge { padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.85rem; font-weight: 600; }
        .badge-critical { background: #f85149; color: white; }
        .badge-high { background: #db6d28; color: white; }
        .badge-medium { background: #d29922; color: white; }
        footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #d0d7de; color: #656d76; text-align: center; font-size: 0.85rem; }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Security Analysis — Executive Summary</h1>
            <p style="color: #656d76; margin-top: 0.5rem;">Target: {{ target }} | Date: {{ timestamp }}</p>
        </div>
    </header>

    <div class="container">
        <div class="summary">
            <h2>Risk Assessment</h2>
            <p>
                {% if critical_count > 0 %}
                <span class="risk-high">CRITICAL RISK:</span> {{ critical_count }} critical vulnerabilities found.
                {% elif high_count > 0 %}
                <span class="risk-high">HIGH RISK:</span> {{ high_count }} high-severity issues found.
                {% elif medium_count > 0 %}
                <span class="risk-medium">MEDIUM RISK:</span> {{ medium_count }} medium-severity issues found.
                {% else %}
                <span class="risk-low">LOW RISK:</span> No critical or high-severity issues found.
                {% endif %}
            </p>
        </div>

        <h2>Key Findings</h2>
        <table>
            <thead>
                <tr><th>Severity</th><th>Finding</th><th>Location</th></tr>
            </thead>
            <tbody>
                {% for finding in findings %}
                {% if finding.severity.value in ['critical', 'high', 'medium'] %}
                <tr>
                    <td><span class="badge badge-{{ finding.severity.value }}">{{ finding.severity.value | upper }}</span></td>
                    <td>{{ finding.title }}</td>
                    <td>{{ finding.location }}</td>
                </tr>
                {% endif %}
                {% endfor %}
            </tbody>
        </table>

        <h2>Statistics</h2>
        <p>Total findings: {{ total_findings }}</p>
        <ul>
            <li>Critical: {{ critical_count }}</li>
            <li>High: {{ high_count }}</li>
            <li>Medium: {{ medium_count }}</li>
            <li>Low: {{ low_count }}</li>
            <li>Info: {{ info_count }}</li>
        </ul>
    </div>

    <footer>
        <p>Generated by redteam-analyzer v{{ version }}</p>
    </footer>
</body>
</html>"""
