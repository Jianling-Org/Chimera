"""Translate selected modules and expose their generated artifacts."""

from .model import (
    TranslatedModule,
    TranslationKey,
    TranslationProductionSpec,
    TranslationRequest,
    variant_id,
)
from .step import TranslationStep

__all__ = [
    "TranslatedModule", "TranslationKey", "TranslationProductionSpec",
    "TranslationRequest", "TranslationStep",
    "variant_id",
]
