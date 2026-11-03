"""
Round-trip test for deliverydb: write an `ArtefactMetadata` entry into a real
(testcontainers) PostgreSQL via the productive session factory and conversion
helpers, and read it back.
"""

import datetime

import pytest

import deliverydb.model as dm
import deliverydb.util
import odg.model


@pytest.fixture
def artefact_metadata() -> odg.model.ArtefactMetadata:
    return odg.model.ArtefactMetadata(
        artefact=odg.model.ComponentArtefactId(
            component_name='github.com/gardener/gardener',
            component_version='1.2.3',
            artefact=odg.model.LocalArtefactId(
                artefact_name='gardener-apiserver',
                artefact_version='1.2.3',
                artefact_type='ociImage',
            ),
            artefact_kind=odg.model.ArtefactKind.ARTEFACT,
        ),
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.OSID,
            type=odg.model.Datatype.OSID,
            creation_date=datetime.datetime.now(),
        ),
        data=odg.model.OperatingSystemId(
            ID='gardenlinux',
            VERSION_ID='1592',
            PRETTY_NAME='Garden Linux 1592',
        ),
        discovery_date=datetime.date.today(),
    )


def test_artefact_metadata_roundtrip(
    db_session,
    artefact_metadata: odg.model.ArtefactMetadata,
):
    db_entry = deliverydb.util.to_db_artefact_metadata(artefact_metadata=artefact_metadata)
    db_session.add(db_entry)
    db_session.commit()

    queried = (
        db_session.query(dm.ArtefactMetaData)
        .filter(
            dm.ArtefactMetaData.id == artefact_metadata.id,
        )
        .one()
    )

    assert queried.component_name == artefact_metadata.artefact.component_name
    assert queried.type == odg.model.Datatype.OSID
    assert queried.datasource == odg.model.Datasource.OSID
    assert queried.data['ID'] == 'gardenlinux'
    assert queried.data['PRETTY_NAME'] == 'Garden Linux 1592'
    assert queried.discovery_date == artefact_metadata.discovery_date

    # re-deserialise via the productive helper and compare against the input;
    # `OSID` is not a Finding model, so `data` stays a raw dict
    roundtripped = odg.model.ArtefactMetadata.from_dict(
        raw=deliverydb.util.db_artefact_metadata_to_dict(artefact_metadata=queried),
    )
    assert roundtripped.data['ID'] == 'gardenlinux'
    assert roundtripped.data['PRETTY_NAME'] == 'Garden Linux 1592'
    assert roundtripped.artefact.artefact.artefact_name == 'gardener-apiserver'
    assert roundtripped.meta.type == artefact_metadata.meta.type


def test_sessions_are_isolated(
    db_session,
    artefact_metadata: odg.model.ArtefactMetadata,
):
    # regression guard for deliverydb's engine cache (keyed on pool params only):
    # this session must point at THIS test's empty database, not a previous one
    assert db_session.query(dm.ArtefactMetaData).count() == 0

    db_entry = deliverydb.util.to_db_artefact_metadata(artefact_metadata=artefact_metadata)
    db_session.add(db_entry)
    db_session.commit()

    assert db_session.query(dm.ArtefactMetaData).count() == 1
