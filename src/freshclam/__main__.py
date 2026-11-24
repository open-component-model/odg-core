#!/usr/bin/env python3

import contextlib
import os
import subprocess
import threading

import starlette.applications
import starlette.responses
import starlette.routing
import starlette.staticfiles
import structlog
import uvicorn

import odg.logging_cfg
import odg.telemetry
import paths

odg.logging_cfg.configure_logging()
odg.logging_cfg.route_foreign_loggers('uvicorn', 'uvicorn.access', 'uvicorn.error')
# drop noisy kubelet probe access-log entries (2xx/3xx; failures still logged)
odg.logging_cfg.quiet_uvicorn_access_log(path_prefixes=('/readiness',))
# serves starlette/uvicorn, not aiohttp — only span export + log/trace identity apply
odg.telemetry.configure_telemetry(instrument_aiohttp=False)


logger = structlog.get_logger(__name__)

status_file = os.path.join('/', 'freshclam', 'status')


async def readiness(request):
    if not os.path.isfile(status_file):
        return starlette.responses.HTMLResponse(status_code=425)

    with open(status_file, 'r') as f:
        status = f.read().strip()

    if status == 'outdated':
        return starlette.responses.HTMLResponse(status_code=400)
    elif status == 'up-to-date':
        return starlette.responses.HTMLResponse(status_code=200)
    else:
        return starlette.responses.HTMLResponse(status_code=501)


def start_server(path, directory, port, debug=False):
    app = starlette.applications.Starlette(
        routes=[
            starlette.routing.Route(path='/readiness', endpoint=readiness, methods=['GET']),
        ],
        debug=debug,
    )
    f = starlette.staticfiles.StaticFiles(directory=directory)
    app.mount(path, f)

    uvicorn.run(app, host='0.0.0.0', port=port, log_config=None)


def write_status(status: str) -> None:
    with open(status_file, 'w') as f:
        f.write(status)


def clear_status() -> None:
    with contextlib.suppress(FileNotFoundError):
        os.remove(status_file)


def verify_database_and_start_daemon() -> None:
    # the status file survives a container restart in the same pod (emptyDir),
    # so this container must verify the database itself before it may report
    # ready; freshclam without --daemon performs a single foreground check and
    # exits 0 whether it updated the database or found it still current, hence
    # readiness also recovers when the daemon's OnUpdateExecute hook never runs
    check_result = subprocess.run(
        args=[
            'freshclam',
            '--config-file',
            paths.freshclam_config_path,
        ],
    )

    if check_result.returncode == 0:
        write_status('up-to-date')
        logger.info('virus database verified as up-to-date')
    else:
        write_status('outdated')
        logger.error(
            'virus database check failed',
            returncode=check_result.returncode,
        )

    daemon_result = subprocess.run(
        args=[
            'freshclam',
            '--daemon',
            '--config-file',
            paths.freshclam_config_path,
        ],
    )

    if daemon_result.returncode != 0:
        write_status('outdated')
        logger.error(
            'freshclam daemon failed to start',
            returncode=daemon_result.returncode,
        )


def main():
    # invalidate a status retained from a previous container so readiness
    # cannot pass before this container verified the database
    clear_status()
    threading.Thread(target=verify_database_and_start_daemon, daemon=True).start()
    start_server('/', '/www', 8080)


if __name__ == '__main__':
    main()
