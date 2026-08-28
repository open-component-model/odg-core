import functools

import odg.extensions_cfg
import odg.findings
import odg.model
import odg.util
import paths
import scanner_utils.orchestrator
import trivy_extension.scanner


def main():
    parsed_arguments = odg.util.parse_args()
    vulnerability_cfg = odg.findings.Finding.from_file(
        path=parsed_arguments.findings_cfg_path or paths.findings_cfg_path(),
        finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
    )
    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.TRIVY,
        callback=functools.partial(
            scanner_utils.orchestrator.run_scan,
            scanner=trivy_extension.scanner.TrivyScanner(),
            datasource=odg.model.Datasource.TRIVY,
            vulnerability_cfg=vulnerability_cfg,
        ),
    )


if __name__ == '__main__':
    main()
