import os


ini_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'alembic.ini')


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    # exclude unnamed indexes (SQLAlchemy auto-naming differs between
    # create_all and alembic runs and would cause endless drop/re-add diffs)
    if type_ == 'index' and not name:
        return False
    return True
