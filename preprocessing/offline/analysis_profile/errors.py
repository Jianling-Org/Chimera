"""Workflow profile and registry errors."""


class ProfileError(ValueError):
    """The ``[profile]`` table cannot select a supported workflow."""


class RebuildMissingUpstream(RuntimeError):
    """A replay callback could not reconstruct its declared outputs."""


class BuildReplayPropertyError(RebuildMissingUpstream):
    """A manifest property required by a replay callback is missing/invalid."""


__all__ = ["ProfileError", "RebuildMissingUpstream", "BuildReplayPropertyError"]
