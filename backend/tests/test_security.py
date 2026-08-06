"""
SafeSOC — Password Hashing Tests
"""

from app.core.security import hash_password, verify_password


def test_hash_password_does_not_return_the_plaintext_password():
    hashed = hash_password("correct-horse-battery-staple")

    assert hashed != "correct-horse-battery-staple"
    assert hashed.startswith("$2b$")


def test_verify_password_round_trip_succeeds_for_correct_password():
    hashed = hash_password("correct-horse-battery-staple")

    assert verify_password("correct-horse-battery-staple", hashed) is True


def test_verify_password_round_trip_fails_for_incorrect_password():
    hashed = hash_password("correct-horse-battery-staple")

    assert verify_password("wrong-password", hashed) is False


def test_hash_password_produces_distinct_hashes_for_same_password():
    # bcrypt salts each hash, so two hashes of the same password must differ.
    assert hash_password("hunter2") != hash_password("hunter2")
