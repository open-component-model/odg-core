"""
Contains key constants to access variables embedded in the applications' or requests' context. Both
are dict-like objects, so the constants can be used to retrieve the desired variables like they were
globally available.
"""

APP_BASE_URL = 'base_url'
APP_COMPONENT_DESCRIPTOR_LOOKUP = 'component_descriptor_lookup'
APP_EOL_CLIENT = 'eol_client'
APP_GITHUB_API_LOOKUP = 'github_api_lookup'
APP_GITHUB_REPO_LOOKUP = 'github_repo_lookup'
APP_KUBERNETES_API = 'kubernetes_api'
APP_NAMESPACE = 'namespace'
APP_OCI_CLIENT = 'oci_client'

# `db_session` is intended to be used for tasks which have to be finished in a timely manner
REQUEST_DB_SESSION = 'db_session'
# `db_session_low_prio` has a small connection pool with a long timeout for low prio tasks
REQUEST_DB_SESSION_LOW_PRIO = 'db_session_low_prio'
REQUEST_USER_ID = 'user_id'
REQUEST_USER_ROLES = 'user_roles'

BACKLOG_ITEM_SLEEP_INTERVAL_SECONDS = 60
RESCORING_OPERATOR_SET_TO_PREFIX = 'set-to-'
