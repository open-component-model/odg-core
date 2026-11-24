import odg.model
import issue_replicator.github as gh


def test_sanitise_md_table_cell_escapes_pipe_and_backtick():
    assert gh._sanitise_md_table_cell('a|b`c') == 'a\\|b\\`c'


def test_sanitise_md_table_cell_normal_text_is_unchanged():
    assert gh._sanitise_md_table_cell('github.com/org/repo') == 'github.com/org/repo'
    assert gh._sanitise_md_table_cell('CVE-2024-1234') == 'CVE-2024-1234'
    assert gh._sanitise_md_table_cell('') == ''


def test_sanitise_md_table_cell_malicious_table_breakout():
    # a scanner-derived value crafted to break out of the table cell and inject markdown
    malicious = 'x | y\n\n[malicious](https://evil.example) `code`'
    sanitised = gh._sanitise_md_table_cell(malicious)

    assert '|' not in sanitised.replace('\\|', '')
    assert '`' not in sanitised.replace('\\`', '')
    assert sanitised == 'x \\| y\n\n[malicious](https://evil.example) \\`code\\`'


def test_sanitise_md_table_cell_accepts_non_string_values():
    # JSON-derived values may be dicts, lists, ints, ... and must not crash the helper
    assert gh._sanitise_md_table_cell({'dev': 'a|b'}) == "{'dev': 'a\\|b'}"
    assert gh._sanitise_md_table_cell(['x', 1]) == "['x', 1]"
    assert gh._sanitise_md_table_cell(42) == '42'
    assert gh._sanitise_md_table_cell(None) == 'None'


def test_redact_secret_keeps_edges_and_escapes_markdown():
    # first/last 4 chars visible, middle replaced by redacted count
    assert gh._redact_secret('abcd|e`fghijk') == 'abcd***5***hijk'


def test_redact_secret_escapes_markdown_in_visible_edges():
    assert gh._redact_secret('ab|dxxxxef`g') == 'ab\\|d***4***ef\\`g'


def test_redact_secret_short_secret_is_fully_masked():
    assert gh._redact_secret('shortone') == '***8***'
    assert gh._redact_secret('a|b') == '***3***'


def test_artefact_to_str_html_escapes_values():
    artefact = odg.model.ComponentArtefactId(
        component_name='comp',
        component_version='1.0',
        artefact_kind=odg.model.ArtefactKind.RESOURCE,
        artefact=odg.model.LocalArtefactId(
            artefact_name='a<b>',
            artefact_version='1&2',
            artefact_type='ociImage',
            artefact_extra_id={'platform': 'linux/amd64'},
        ),
    )

    id_str = gh._artefact_to_str(artefact)

    assert 'a&lt;b&gt;' in id_str
    assert '1&amp;2' in id_str
    assert 'a<b>' not in id_str
