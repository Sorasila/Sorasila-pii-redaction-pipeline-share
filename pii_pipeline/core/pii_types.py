from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final


class PiiType(StrEnum):
    """Canonical labels shared by detectors, placeholders, and LLM contracts."""

    PERSON_NAME = "NAME"
    JURISTIC_PERSON_NAME = "ORGANIZATION"
    NATIONAL_ID = "ID_NUMBER"
    PASSPORT_NUMBER = "PASSPORT_NUMBER"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    FAX = "FAX"
    ADDRESS = "ADDRESS"
    BANK_ACCOUNT_NUMBER = "BANK_ACCOUNT_NUMBER"
    PAYMENT_CARD_NUMBER = "PAYMENT_CARD_NUMBER"
    VEHICLE_REGISTRATION = "VEHICLE_REGISTRATION"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    SOCIAL_MEDIA_IDENTIFIER = "SOCIAL_MEDIA_IDENTIFIER"
    LAND_PARCEL_NUMBER = "LAND_PARCEL_NUMBER"
    CASE_NUMBER = "CASE_NUMBER"
    TITLE_DEED_NUMBER = "TITLE_DEED_NUMBER"
    OFFICIAL_LETTER_NUMBER = "OFFICIAL_LETTER_NUMBER"


CANONICAL_PII_TYPES: tuple[str, ...] = tuple(pii_type.value for pii_type in PiiType)
CANONICAL_PII_TYPE_SET: frozenset[str] = frozenset(CANONICAL_PII_TYPES)
PII_TYPE_SCOPE_NOTES: Final[Mapping[str, str]] = MappingProxyType(
    {
        PiiType.JURISTIC_PERSON_NAME.value: (
            "Private juristic persons only, such as companies, partnerships, "
            "foundations or associations. "
            "Government agencies, courts and their units are not ORGANIZATION "
            "even though they are juristic persons in law."
        ),
        PiiType.LAND_PARCEL_NUMBER.value: (
            "Land parcel number only; exclude title-deed number, survey-page number, "
            "and cadastral-map sheet or grid reference."
        ),
        PiiType.CASE_NUMBER.value: (
            "Black/red court case numbers: one or more digits or one or more "
            "Thai letters, slash, exactly four Buddhist-era year digits. "
            "Preserve the case field label."
        ),
        PiiType.TITLE_DEED_NUMBER.value: (
            "Land title-deed numbers, including land-use certificate numbers "
            "after 'น.ส. 3' or 'น.ส. 3 ก.'; distinct from land parcel numbers. "
            "Preserve the title-deed field label."
        ),
        PiiType.OFFICIAL_LETTER_NUMBER.value: (
            "Official letter reference numbers after 'หนังสือที่': agency "
            "letters, a number that may contain periods, slash, running number. "
            "Preserve the 'หนังสือที่' label."
        ),
    }
)


def canonicalize_pii_type(pii_type: object) -> str:
    """Normalize a type label and reject values outside the shared contract."""

    if not isinstance(pii_type, str):
        raise TypeError("Invalid canonical PII type")

    canonical_type = pii_type.strip().upper()

    if canonical_type not in CANONICAL_PII_TYPE_SET:
        raise ValueError("Invalid canonical PII type")

    return canonical_type
