<%! import html %>
# 📋 SLA Violation Report

% if delivery_service_url:
Source: ODG api at ${delivery_service_url | h}.
% endif

Report for component **${component_name | h}**, version **${selected_version | h}**.

% if not profiled:
⚠️ The SLA violation profiler has not run for this version yet, so there is no data to report. Once the profiler has processed this version, re-run this report.
% elif total_violation_count == 0:
✅ No SLA violations recorded for this version.
% else:
🚨 ${total_violation_count} individual violation(s).

Each violation below points to the **OCM component and artefact version that actually carries the vulnerability** — this is what a team needs to fix — mapped to the CVE which caused the violation.

<details open>
  <summary><h1>🚦 Violations by severity (${len(severity_rows)})</h1></summary>

Severity is taken from the vulnerability finding each violation references, with any rescoring applied (the latest rescoring wins). The counts below sum to the total above.

| Severity | Violations |
|----|----:|
% for emoji, severity, count in severity_rows:
| ${emoji} ${severity} | ${count} |
% endfor
</details>

# 🔧 What to fix (${len(artefact_sections)} artefact(s))

Each artefact below carries the listed CVEs; fix or rescore them. Responsibles are resolved from the delivery-service.

% for section in artefact_sections:
<details>
  <summary><h1>📦 ${section.component_name | h} / ${section.artefact_name | h} @ ${section.version | h} (${section.violation_count})</h1></summary>

% if section.responsibles:
Responsibles: ${', '.join(section.responsibles) | h}
% else:
Responsibles: _none resolved_
% endif

<table>
<thead>
<tr><th>Severity</th><th>CVE</th><th>Package</th><th>Summary</th></tr>
</thead>
<tbody>
% for row in section.cve_rows:
<tr>
<td>${row.emoji} ${row.severity | h}</td>
<td>${row.cve | h}</td>
<td>${row.package | h}</td>
<td>\
% if row.events:
<details><summary>${row.summary | h}</summary><br>${'<br>'.join(f"{ev.emoji} {html.escape(ev.comment)}" for ev in row.events)}</details>\
% else:
${row.summary | h}\
% endif
</td>
</tr>
% endfor
</tbody>
</table>
</details>

% endfor
% endif
