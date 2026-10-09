import re

from backend.detection.owasp_map import OWASP_MAP


PROJECT_DETECTOR_NAMES = {
    "bola",
    "bola_detector",
    "enumeration",
    "enumeration_detector",
    "login_failure",
    "login_failure_detector",
    "rate_detector",
    "rate_spike",
    "ml_score",
}
REQUIRED_FIELDS = {
    "owasp_id",
    "name",
    "what_we_detect",
    "what_we_dont",
}
VALID_OWASP_ID = re.compile(r"API(?:[1-9]|10):2023\Z")


def test_every_project_detection_signal_has_an_owasp_mapping():
    assert PROJECT_DETECTOR_NAMES <= OWASP_MAP.keys()


def test_every_mapping_has_required_fields_and_valid_owasp_id():
    for mapping in OWASP_MAP.values():
        assert REQUIRED_FIELDS <= mapping.keys()
        assert isinstance(mapping["owasp_id"], str)
        assert (
            mapping["owasp_id"] == "N/A"
            or VALID_OWASP_ID.fullmatch(mapping["owasp_id"])
        )
        assert mapping["name"]
        assert mapping["what_we_detect"]
        assert mapping["what_we_dont"]


def test_detector_names_map_to_expected_categories():
    assert OWASP_MAP["bola"]["owasp_id"] == "API1:2023"
    assert OWASP_MAP["bola_detector"]["owasp_id"] == "API1:2023"
    assert OWASP_MAP["enumeration"]["owasp_id"] == "API1:2023"
    assert OWASP_MAP["enumeration_detector"]["owasp_id"] == "API1:2023"
    assert OWASP_MAP["login_failure"]["owasp_id"] == "API2:2023"
    assert OWASP_MAP["login_failure_detector"]["owasp_id"] == "API2:2023"
    assert OWASP_MAP["rate_spike"]["owasp_id"] == "API4:2023"
    assert OWASP_MAP["rate_detector"]["owasp_id"] == "API4:2023"
    assert OWASP_MAP["ml_score"]["owasp_id"] == "N/A"
