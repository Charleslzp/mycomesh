from __future__ import annotations

import unittest

from gateway.relay import RelaySchedulingError, _validate_scheduled_receipt_binding


def _authorization(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "request_id": "0x" + "11" * 32,
        "request_hash": "0x" + "22" * 32,
        "key": "0x" + "33" * 20,
        "relay": "0x" + "44" * 20,
        "relay_signer": "0x" + "55" * 20,
        "channel": "0x" + "66" * 32,
        "pricing_version": 1,
        "pricing_hash": "0x" + "77" * 32,
        "max_fee": 100,
        "issued_at": 1000,
        "deadline": 1100,
    }
    value.update(overrides)
    return value


class RelayReceiptBindingTests(unittest.TestCase):
    def test_matching_authorization_is_accepted(self) -> None:
        expected = _authorization()
        signed = {"authorization": {"authorization": dict(expected)}}
        _validate_scheduled_receipt_binding(expected, signed)

    def test_different_request_id_is_rejected_before_settlement(self) -> None:
        expected = _authorization()
        actual = dict(expected)
        actual["request_id"] = "0x" + "99" * 32
        signed = {"authorization": {"authorization": actual}}
        with self.assertRaisesRegex(RelaySchedulingError, "request_id"):
            _validate_scheduled_receipt_binding(expected, signed)

    def test_missing_nested_authorization_is_rejected(self) -> None:
        with self.assertRaises(RelaySchedulingError):
            _validate_scheduled_receipt_binding(_authorization(), {"authorization": {}})

    def test_incomplete_expected_authorization_is_not_a_test_adapter_bypass(self) -> None:
        actual = _authorization()
        for missing in actual:
            with self.subTest(missing=missing):
                expected = {key: value for key, value in actual.items() if key != missing}
                with self.assertRaises(RelaySchedulingError):
                    _validate_scheduled_receipt_binding(expected, {"authorization": {"authorization": actual}})

    def test_every_authorization_field_is_bound(self) -> None:
        expected = _authorization()
        for field, value in expected.items():
            with self.subTest(field=field):
                actual = dict(expected)
                actual[field] = value + 1 if isinstance(value, int) else ("0x" + "ab" * ((len(value) - 2) // 2))
                with self.assertRaisesRegex(RelaySchedulingError, field):
                    _validate_scheduled_receipt_binding(expected, {"authorization": {"authorization": actual}})

    def test_boolean_is_not_an_integer_authorization_field(self) -> None:
        actual = _authorization(pricing_version=True)
        with self.assertRaises(RelaySchedulingError):
            _validate_scheduled_receipt_binding(_authorization(), {"authorization": {"authorization": actual}})


if __name__ == "__main__":
    unittest.main()
