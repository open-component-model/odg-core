import aiohttp.web
import github3.exceptions

import features
import util


def retrieve_version(
    version_cfg: odg.extensions_cfg.CurrentVersion | None,
    component_id: str,
) -> str | None:
    if not version_cfg:
        return None
    try:
        return version_cfg.retrieve()
    except (ValueError, github3.exceptions.NotFoundError) as e:
        raise aiohttp.web.HTTPUnprocessableEntity(
            reason=f'special component {component_id!r} has a misconfigured '
            f'currentVersion.source.repo: {e}',
        )


class CurrentDependencies(aiohttp.web.View):
    required_features = (features.FeatureSpecialComponents,)

    async def get(self):
        """
        ---
        tags:
        - Components
        parameters:
        - in: query
          name: id
          required: true
          schema:
            type: string
        responses:
          "200":
            description: Success
            content:
              application/json:
                schema:
                  type: object
        """
        params = self.request.rel_url.query

        id = util.param(params, 'id', required=True)

        if not (
            component_cfg := features.get_feature(
                features.FeatureSpecialComponents,
            ).find_special_component(id)
        ):
            return aiohttp.web.json_response(
                data={},
            )

        resolved_dependencies = [
            {
                'name': dependency.name,
                'displayName': dependency.displayName,
                'version': retrieve_version(dependency.currentVersion, dependency.name),
            }
            for dependency in component_cfg.dependencies
        ]

        return aiohttp.web.json_response(
            data={
                'displayName': component_cfg.displayName,
                'componentDependencies': resolved_dependencies,
                'version': retrieve_version(component_cfg.currentVersion, id),
            },
        )
