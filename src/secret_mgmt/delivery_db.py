import dataclasses

from sqlalchemy.engine import URL


@dataclasses.dataclass(kw_only=True)
class DeliveryDB:
    username: str = 'postgres'
    password: str
    hostname: str | None = None
    port: int = 5432
    database: str | None = None

    def connection_url(
        self,
        namespace: str,
        service_name: str = 'delivery-db',
        schema: str = 'postgresql+psycopg',
    ) -> str:
        """
        Build a SQLAlchemy connection URL. If `hostname` is set on this instance (external DB),
        `namespace` and `service_name` are ignored. Otherwise both are used to resolve
        the in-cluster DNS name `<service_name>.<namespace>.svc.cluster.local`.
        """
        if self.hostname:
            hostname = self.hostname
        else:
            hostname = f'{service_name}.{namespace}.svc.cluster.local'
        return URL.create(
            drivername=schema,
            username=self.username,
            password=self.password,
            host=hostname,
            port=self.port,
            database=self.database or None,
        ).render_as_string(hide_password=False)
