"""Safety barriers: authorization, scope validation, rate limiting.

This package sits in front of every scan request; the checks here
cannot be bypassed (Chain of Responsibility pattern).
"""
