"""
Example: Well-structured AI-generated code that passes the review pipeline.

This module was scaffolded with GitHub Copilot and reviewed using the
AI Code Review Framework. Demonstrates patterns that achieve high
first-draft acceptance rates.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class UserProfile:
    """Immutable user profile record."""

    user_id: int
    username: str
    email: str
    hashed_password: str

    @classmethod
    def create(cls, user_id: int, username: str, email: str, password: str) -> "UserProfile":
        """
        Create a UserProfile, hashing the password with SHA-256.

        Args:
            user_id: Unique integer identifier.
            username: Display name (max 64 chars).
            email: Validated email address.
            password: Plaintext password (hashed before storage).

        Returns:
            A new UserProfile instance with a hashed password.

        Raises:
            ValueError: If username or email are empty.
        """
        if not username or not username.strip():
            raise ValueError("username must not be empty")
        if not email or "@" not in email:
            raise ValueError("email must be a valid address")

        hashed = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return cls(user_id=user_id, username=username.strip(), email=email, hashed_password=hashed)

    def verify_password(self, candidate: str) -> bool:
        """Return True if candidate matches the stored hashed password."""
        return hashlib.sha256(candidate.encode("utf-8")).hexdigest() == self.hashed_password


def load_profiles_from_csv(path: Path) -> list[UserProfile]:
    """
    Load user profiles from a CSV file with columns: id,username,email,hashed_password.

    Args:
        path: Path to the CSV file.

    Returns:
        List of UserProfile instances.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If a row has an unexpected number of columns.
    """
    if not path.exists():
        raise FileNotFoundError(f"Profile CSV not found: {path}")

    profiles: list[UserProfile] = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) != 4:
                raise ValueError(
                    f"Line {lineno}: expected 4 columns, got {len(parts)}: {line!r}"
                )
            user_id_str, username, email, hashed = parts
            try:
                user_id = int(user_id_str)
            except ValueError:
                raise ValueError(f"Line {lineno}: user_id must be an integer, got {user_id_str!r}")
            profiles.append(
                UserProfile(
                    user_id=user_id,
                    username=username,
                    email=email,
                    hashed_password=hashed,
                )
            )
    return profiles


def find_user_by_email(profiles: list[UserProfile], email: str) -> Optional[UserProfile]:
    """
    Search profiles for a user with the given email (case-insensitive).

    Args:
        profiles: List of UserProfile objects to search.
        email: Email address to look up.

    Returns:
        Matching UserProfile, or None if not found.
    """
    if not profiles:
        return None
    normalized = email.lower().strip()
    return next(
        (p for p in profiles if p.email.lower() == normalized), None
    )


def get_db_connection_string() -> str:
    """
    Return a database connection string from environment variables.

    Returns:
        Connection string.

    Raises:
        RuntimeError: If DATABASE_URL is not set.
    """
    url = os.getenv("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    return url
