import re

from app.schemas.ioc import IndicatorType, IOCCreate


def normalize_ioc(ioc: IOCCreate) -> dict:
    """
    Normalize IOC values into a consistent CTIP representation.
    """

    value = ioc.value.strip()

    if ioc.indicator_type in {
        IndicatorType.DOMAIN,
        IndicatorType.EMAIL,
    }:
        value = value.lower()

    elif ioc.indicator_type == IndicatorType.CVE:
        value = value.upper()

        if not value.startswith("CVE-"):
            value = f"CVE-{value}"

    elif ioc.indicator_type in {
        IndicatorType.HASH_MD5,
        IndicatorType.HASH_SHA1,
        IndicatorType.HASH_SHA256,
    }:
        value = value.lower().replace(" ", "")

    elif ioc.indicator_type == IndicatorType.URL:
        value = value.strip()

    return {
        **ioc.model_dump(),
        "normalized_value": value,
    }