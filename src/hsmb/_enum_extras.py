# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import enum


class OptionalIntEnum(enum.IntEnum):
    """Enum that does not raise an exception when building from unknown value."""

    @classmethod
    def _missing_(cls, value: object) -> enum.Enum | None:
        if not isinstance(value, int):
            return None
        value = int(value)

        new_member = int.__new__(cls, value)
        new_member._name_ = f"Unknown_{cls.__name__}_{str(value).replace('-', '_')}"
        new_member._value_ = value
        return cls._value2member_map_.setdefault(value, new_member)
