"""Shared fail-closed errors for the seal module. Nothing in seal ever downgrades silently."""


class SealError(Exception):
    pass


class TierUnavailable(SealError):
    """A proof tier was requested and no working prover is registered for it."""


class SignatureUnavailable(SealError):
    """A signature algorithm was requested and no working implementation is registered for it."""
