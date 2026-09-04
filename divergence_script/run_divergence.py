# Databricks notebook source
# DBTITLE 1,Setup
import logging
import sys
from pathlib import Path


# --- Resolve notebook directory ---
def get_notebook_dir() -> Path:
    nb_path = (
        dbutils.notebook.entry_point.getDbutils()
        .notebook()
        .getContext()
        .notebookPath()
        .get()
    )
    return Path("/Workspace") / Path(nb_path).parent.relative_to("/")

NOTEBOOK_DIR = get_notebook_dir()
PARENT_DIR = NOTEBOOK_DIR.parent

# PARENT_DIR contains the `divergence` package. Needed for `import divergence`.
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))


def _evict_project_modules() -> None:
    """Drop cached project modules so the next import picks up edits."""
    for mod_name in [m for m in sys.modules if m.split(".")[0] == "divergence"]:
        del sys.modules[mod_name]

# COMMAND ----------

# DBTITLE 1,Run divergence checker
# Configure logging in this cell so the StreamHandler binds to this cell's stdout
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
    force=True,
)

# Evict project modules so the next import picks up code edits
_evict_project_modules()

from divergence.python.__main__ import _run

await _run()

print("Done.")
