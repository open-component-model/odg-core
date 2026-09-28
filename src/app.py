#!/usr/bin/env python3
import argparse
import asyncio
import concurrent.futures
import logging
import os

import aiohttp.web
import aiohttp.web_log
import aiohttp_swagger3

import ci.log

import artefacts
import blobstore.blob
import compliance_tests
import components
import consts
import deliverydb.cache_async
import dora
import eol
import features
import k8s.util
import lookups
import metadata
import middleware.auth
import middleware.cors
import middleware.db_session
import middleware.errors
import middleware.prometheus
import middleware.route_feature_check as rfc
import osinfo
import paths
import rescore.artefacts
import service_extensions
import special_component
import sprints

ci.log.configure_default_logging(print_thread_id=True)
logger = logging.getLogger(__name__)

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--productive', action='store_true', default=False)
    parser.add_argument('--port', default=5000, type=int)
    parser.add_argument('--max-workers', default=4, type=int)
    parser.add_argument('--shortcut-auth', action='store_true', default=False)
    parser.add_argument('--delivery-db-url', default=None)
    parser.add_argument('--cache-dir', default=default_cache_dir)
    parser.add_argument(
        '--k8s-cfg-name',
        help='specify kubernetes cluster to interact with extensions (and logs)',
    )
    parser.add_argument(
        '--kubeconfig',
        help="""
            specify kubernetes cluster to interact with extensions (and logs); if both
            `k8s-cfg-name` and `kubeconfig` are set, `k8s-cfg-name` takes precedence
        """,
    )
    parser.add_argument(
        '--k8s-namespace',
        help='specify kubernetes cluster namespace to interact with extensions (and logs)',
    )

    return parser.parse_args()


def get_base_url(
    is_productive: bool,
    kubernetes_api: k8s.util.KubernetesApi | None = None,
    namespace: str | None = None,
    port: int | None = None,
) -> str:
    if not is_productive or not kubernetes_api:
        return f'http://localhost:{port}'

    http_route = kubernetes_api.custom_kubernetes_api.get_namespaced_custom_object(
        group='gateway.networking.k8s.io',
        version='v1',
        plural='httproutes',
        name='delivery-service',
        namespace=namespace,
    )
    host = http_route['spec']['hostnames'][0]

    return f'https://{host}'


def add_app_context_vars(
    app: aiohttp.web.Application,
    parsed_arguments,
) -> aiohttp.web.Application:
    oci_client = lookups.semver_sanitising_oci_client_async()

    def db_url_callback() -> str | None:
        return parsed_arguments.delivery_db_url or middleware.db_session.incluster_db_url()

    component_descriptor_lookup = lookups.init_component_descriptor_lookup_async(
        cache_dir=parsed_arguments.cache_dir,
        db_url_callback=db_url_callback,
        oci_client=oci_client,
    )

    github_api_lookup = lookups.github_api_lookup()
    github_repo_lookup = lookups.github_repo_lookup(github_api_lookup)

    cluster_access_feature = features.get_feature(features.FeatureClusterAccess)
    if cluster_access_feature.state is features.FeatureStates.AVAILABLE:
        cluster_access_feature: features.FeatureClusterAccess

        kubernetes_api = cluster_access_feature.get_kubernetes_api()
        namespace = cluster_access_feature.get_namespace()
    else:
        kubernetes_api = None
        namespace = None

    base_url = get_base_url(
        is_productive=parsed_arguments.productive,
        kubernetes_api=kubernetes_api,
        namespace=namespace,
        port=parsed_arguments.port,
    )

    app[consts.APP_BASE_URL] = base_url
    app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP] = component_descriptor_lookup
    app[consts.APP_EOL_CLIENT] = eol.EolClient()
    app[consts.APP_GITHUB_API_LOOKUP] = github_api_lookup
    app[consts.APP_GITHUB_REPO_LOOKUP] = github_repo_lookup
    app[consts.APP_KUBERNETES_API] = kubernetes_api
    app[consts.APP_NAMESPACE] = namespace
    app[consts.APP_OCI_CLIENT] = oci_client

    return app


@middleware.auth.noauth
class Ready(aiohttp.web.View):
    async def get(self):
        """
        ---
        description: This endpoint allows to test that the service is up and running.
        tags:
        - Health check
        responses:
          "200":
            description: Service is up and running
        """
        return aiohttp.web.Response()


def add_routes(
    swagger: aiohttp_swagger3.SwaggerDocs,
) -> aiohttp_swagger3.SwaggerDocs:
    swagger.add_view(
        path='/ready',
        handler=Ready,
    )

    swagger.add_view(
        path='/features',
        handler=features.Features,
    )

    # dedicated route instead of `/features` route to allow unauthorised retrieval (-> login page)
    swagger.add_view(
        path='/profiles',
        handler=features.Profiles,
    )

    swagger.add_view(
        path='/ocm/artefacts/blob',
        handler=artefacts.ArtefactBlob,
    )

    swagger.add_view(
        path='/artefacts/metadata',
        handler=metadata.ArtefactMetadata,
    )
    swagger.add_view(
        path='/artefacts/metadata/query',
        handler=metadata.ArtefactMetadataQuery,
    )

    swagger.add_view(
        path='/components/upgrade-prs',
        handler=components.UpgradePRs,
    )

    swagger.add_view(
        path='/components/diff',
        handler=components.ComponentDescriptorDiff,
    )

    swagger.add_view(
        path='/special-component/current-dependencies',
        handler=special_component.CurrentDependencies,
    )

    swagger.add_view(
        path='/components/tests',
        handler=compliance_tests.DownloadTestResults,
    )

    swagger.add_view(
        path='/components/compliance-summary',
        handler=components.ComplianceSummary,
    )

    swagger.add_view(
        path='/components/sbom',
        handler=components.DownloadSBOM,
    )

    swagger.add_view(
        path='/delivery/sprint-infos',
        handler=sprints.SprintInfos,
    )
    swagger.add_view(
        path='/delivery/sprint-infos/current',
        handler=sprints.SprintInfosCurrent,
    )

    swagger.add_view(
        path='/auth',
        handler=middleware.auth.OAuthLogin,
    )
    swagger.add_view(
        path='/auth/refresh',
        handler=middleware.auth.OAuthRefresh,
    )
    swagger.add_view(
        path='/auth/logout',
        handler=middleware.auth.OAuthLogout,
    )
    swagger.add_view(
        path='/auth/configs',
        handler=middleware.auth.OAuthCfgs,
    )
    swagger.add_view(
        path='/auth/rbac',
        handler=middleware.auth.Rbac,
    )
    swagger.add_view(
        path='/auth/user',
        handler=middleware.auth.User,
    )

    # endpoint according to OpenID provider configuration request
    # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
    swagger.add_view(
        path='/.well-known/openid-configuration',
        handler=middleware.auth.OpenIDCfg,
    )
    swagger.add_view(
        path='/openid/v1/jwks',
        handler=middleware.auth.OpenIDJwks,
    )

    swagger.add_view(
        path='/ocm/component',
        handler=components.Component,
    )
    swagger.add_view(
        path='/ocm/component/versions',
        handler=components.GreatestComponentVersions,
    )
    swagger.add_view(
        path='/ocm/component/dependencies',
        handler=components.ComponentDependencies,
    )
    swagger.add_view(
        path='/ocm/component/responsibles',
        handler=components.ComponentResponsibles,
    )
    swagger.add_view(
        path='/os/{os_id}/branches',
        handler=osinfo.OsInfoRoutes,
    )
    swagger.add_view(
        path='/rescore',
        handler=rescore.artefacts.Rescore,
    )

    swagger.add_view(
        path='/service-extensions',
        handler=service_extensions.ServiceExtensions,
    )
    swagger.add_view(
        path='/service-extensions/log-collections',
        handler=service_extensions.LogCollections,
    )
    swagger.add_view(
        path='/service-extensions/container-statuses',
        handler=service_extensions.ContainerStatuses,
    )
    swagger.add_view(
        path='/service-extensions/backlog-items',
        handler=service_extensions.BacklogItems,
    )
    swagger.add_view(
        path='/service-extensions/runtime-artefacts',
        handler=service_extensions.RuntimeArtefacts,
    )
    swagger.add_view(
        path='/dora/dora-metrics',
        handler=dora.DoraMetrics,
    )
    swagger.add_view(
        path='/metrics',
        handler=middleware.prometheus.Metrics,
    )
    swagger.add_view(
        path='/cache',
        handler=deliverydb.cache_async.DeliveryDBCache,
    )
    swagger.add_view(
        path='/artefacts/metadata/query-attributes',
        handler=metadata.ArtefactMetadataQueryAttributes,
    )
    swagger.add_view(
        path='/artefacts/metadata/query/by-search-expression',
        handler=metadata.ArtefactMetadataQueryBySearchExpression,
    )

    swagger.add_view(
        path='/blob',
        handler=blobstore.blob.Blob,
    )
    return swagger


async def initialise_app():
    parsed_arguments = parse_args()

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=parsed_arguments.max_workers)
    loop = asyncio.get_running_loop()
    loop.set_default_executor(executor)

    if parsed_arguments.shortcut_auth:
        default_auth = middleware.auth.AuthType.NONE
    else:
        default_auth = middleware.auth.AuthType.BEARER

    middlewares = (
        middleware.cors.cors_middleware(),
        middleware.errors.errors_middleware(),
        middleware.auth.auth_middleware(default_auth=default_auth),
        middleware.db_session.db_session_middleware(db_url=parsed_arguments.delivery_db_url),
        rfc.feature_check_middleware(),
    )

    await features.init_features(parsed_arguments)

    if available_features := tuple(
        f for f in features.feature_cfgs if f.state is features.FeatureStates.AVAILABLE
    ):
        logger.info(
            f'The following feature{"s are" if len(available_features) != 1 else " is"} '
            f'active: {", ".join(sorted(f.name for f in available_features))}',
        )

    if unavailable_features := tuple(
        f for f in features.feature_cfgs if f.state is features.FeatureStates.UNAVAILABLE
    ):
        logger.info(
            f'The following feature{"s are" if len(unavailable_features) != 1 else " is"} '
            f'inactive: {", ".join(sorted(f.name for f in unavailable_features))}',
        )

    app = aiohttp.web.Application(
        middlewares=middlewares,
        client_max_size=0,
    )
    # Register on_response_prepare signal handler for CORS headers
    # This ensures CORS headers are added before StreamResponse.prepare() is called
    app.on_response_prepare.append(
        lambda request, response: middleware.cors._on_response_prepare_handler(
            request,
            response,
            allow_origins='*',
            allow_credentials='*',
        ),
    )
    app = middleware.prometheus.add_prometheus_middleware(app=app)

    app = add_app_context_vars(
        app=app,
        parsed_arguments=parsed_arguments,
    )

    swagger = aiohttp_swagger3.SwaggerDocs(
        app,
        swagger_ui_settings=aiohttp_swagger3.SwaggerUiSettings(path='/api/v1/doc'),
        components=paths.swagger_path,
        info=aiohttp_swagger3.SwaggerInfo(
            title='Delivery-Service by Gardener CICD',
            version='1.0.0',
            description='API definition',
        ),
        validate=False,  # disabled due to recursive $ref in ComponentArtefactId (valid in OAS 3.0)
    )

    swagger = add_routes(
        swagger=swagger,
    )

    return app


async def run_app():
    parsed_arguments = parse_args()

    port = parsed_arguments.port

    app = await initialise_app()

    if parsed_arguments.productive:
        host = '0.0.0.0'

    else:
        host = '127.0.0.1'
        print('running in development mode')
        print()
        print(f'listening at {host}:{port}')
        print()

    def _format_r(request: aiohttp.web.BaseRequest, *args, **kwargs) -> str:
        if request is None:
            return '-'

        if request.path.startswith('/auth'):
            # use `path` instead of `path_qs` to _not_ log query parameters
            path = request.path
        else:
            path = request.path_qs

        return f'{request.method} {path} HTTP/{request.version.major}.{request.version.minor}'

    aiohttp.web_log.AccessLogger._format_r = _format_r

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    await aiohttp.web.TCPSite(
        runner=runner,
        host=host,
        port=port,
    ).start()

    await asyncio.Event().wait()


if __name__ == '__main__':
    asyncio.run(run_app())
else:
    app = initialise_app
