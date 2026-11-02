import dataclasses


@dataclasses.dataclass
class PPMS:
    username: str
    password: str = dataclasses.field(repr=False)
