"""
CSV file helpers for identity listing and divergence output files.
"""

import csv
from contextlib import contextmanager
from pathlib import Path

from .constants import (
    CSV_HEADERS,
    FAILURES_CSV_HEADERS,
    FAILURES_CSV_PREFIX,
    GATHER_CSV_HEADERS,
    IDENTITY_CSV_PREFIX,
    OUTPUT_CSV_PREFIX,
    OUTPUT_SUFFIXES,
    RESULTS_DIR,
    WORKSPACES_CSV_HEADERS,
    WORKSPACES_CSV_NAME,
)


def divergence_output_path(principal_type):
    """Return the divergence-output CSV path for a principal type."""
    return str(RESULTS_DIR / f"{OUTPUT_CSV_PREFIX}_{OUTPUT_SUFFIXES[principal_type]}.csv")


def identity_gather_path(principal_type):
    """Return the identity listing CSV path for a principal type."""
    return str(RESULTS_DIR / f"{IDENTITY_CSV_PREFIX}_{OUTPUT_SUFFIXES[principal_type]}.csv")


@contextmanager
def open_divergence_output(principal_type, mode):
    """Open a divergence-output CSV file for a single principal type.

    Yields (file_handle, csv_writer) and closes the file on exit.
    """
    file_handle = open(divergence_output_path(principal_type), mode, newline="")
    try:
        writer = csv.DictWriter(file_handle, fieldnames=CSV_HEADERS[principal_type])
        if mode == "w":
            writer.writeheader()
        yield file_handle, writer
    finally:
        file_handle.close()


@contextmanager
def open_gather_identity_files(principal_types):
    """Open identity listing CSV files for writing during identity gathering.

    Yields (file_handles dict, csv_writers dict) and closes all files on exit.
    """
    file_handles = {}
    csv_writers = {}
    try:
        for principal_type in principal_types:
            file_handle = open(identity_gather_path(principal_type), "w", newline="")
            writer = csv.DictWriter(file_handle, fieldnames=GATHER_CSV_HEADERS)
            writer.writeheader()
            file_handles[principal_type] = file_handle
            csv_writers[principal_type] = writer
        yield file_handles, csv_writers
    finally:
        for file_handle in file_handles.values():
            file_handle.close()


def load_gathered_identity_ids(principal_type):
    """Load identity IDs from the gathered listing CSV and return as a list of ints."""
    with open(identity_gather_path(principal_type), newline="") as file_handle:
        reader = csv.DictReader(file_handle)
        return [int(row["id"]) for row in reader]


def count_gathered_identities(principal_type):
    """Return the number of identities written to the gathered listing CSV."""
    with open(identity_gather_path(principal_type), newline="") as file_handle:
        reader = csv.DictReader(file_handle)
        return sum(1 for _ in reader)


def failures_output_path():
    """Return the path for the failures log CSV."""
    return str(RESULTS_DIR / f"{FAILURES_CSV_PREFIX}.csv")


@contextmanager
def open_failures_output(mode):
    """Open the failures CSV for writing or appending.

    Yields (file_handle, csv_writer) and closes the file on exit.
    """
    file_handle = open(failures_output_path(), mode, newline="")
    try:
        writer = csv.DictWriter(file_handle, fieldnames=FAILURES_CSV_HEADERS)
        if mode == "w":
            writer.writeheader()
        yield file_handle, writer
    finally:
        file_handle.close()


def remove_gathered_identities(principal_types):
    """Remove any partial identity listing CSVs from a previous interrupted gather."""
    for principal_type in principal_types:
        Path(identity_gather_path(principal_type)).unlink(missing_ok=True)


def workspaces_output_path():
    """Return the path for the identity-federation-disabled workspaces CSV."""
    return str(RESULTS_DIR / WORKSPACES_CSV_NAME)


@contextmanager
def open_workspaces_output():
    """Open the identity-federation-disabled workspaces CSV for writing.

    Yields (file_handle, csv_writer) and closes the file on exit.
    """
    file_handle = open(workspaces_output_path(), "w", newline="")
    try:
        writer = csv.DictWriter(file_handle, fieldnames=WORKSPACES_CSV_HEADERS)
        writer.writeheader()
        yield file_handle, writer
    finally:
        file_handle.close()
