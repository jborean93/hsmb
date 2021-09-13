# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import enum
import typing


class OptionalIntEnum(enum.IntEnum):
    """Enum that does not raise an exception when building from unknown value."""

    @classmethod
    def _missing_(cls, value: int) -> "OptionalIntEnum":  # type: ignore[override]
        is_negative = value < 0
        if is_negative:
            value = ~value

        member = cls._create_pseudo_member_(value)
        if is_negative:
            member = ~member  # type: ignore[assignment]

        return member

    @classmethod
    def _create_pseudo_member_(cls, value: int) -> "OptionalIntEnum":
        member_map: typing.Dict[int, "OptionalIntEnum"] = cls._value2member_map_  # type: ignore[assignment]

        member = member_map.get(value, None)
        if member is None:
            new_member = int.__new__(cls, value)
            new_member._name_ = str(value)
            new_member._value_ = value

            member = member_map.setdefault(value, new_member)

        return member
