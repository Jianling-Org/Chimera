"""Pinned optional model metadata used by release examples."""

from __future__ import annotations

MODEL_FILENAME = "tinyllama-1.1b-chat-v1.0.Q3_K_S.gguf"
MODEL_SIZE = 500_315_520
MODEL_SHA256 = "6d58c8fbdaa822b004d7ba473f9b9ad4d1ef7c2dd2c4cf9f9856451aa44bf0ca"
MODEL_URL = (
    "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/"
    "resolve/e14b9934fb66bca914841e9c2ce0ef53c07853cf/"
    "tinyllama-1.1b-chat-v1.0.Q3_K_S.gguf"
)
MODEL_REPOSITORY = "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF"
MODEL_REVISION = "e14b9934fb66bca914841e9c2ce0ef53c07853cf"
MODEL_LICENSE = "Apache-2.0"

__all__ = [
    "MODEL_FILENAME",
    "MODEL_LICENSE",
    "MODEL_REPOSITORY",
    "MODEL_REVISION",
    "MODEL_SIZE",
    "MODEL_SHA256",
    "MODEL_URL",
]
