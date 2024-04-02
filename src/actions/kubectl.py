import json
import os
import subprocess
import tempfile

import ops
from kubectl import kubectl


def get_kubeconfig(event: ops.ActionEvent):
    try:
        result = kubectl("config", "view", "-o", "json", "--raw", external=True)
        # JSON format verification
        kubeconfig = json.dumps(json.loads(result))
        event.set_results({"kubeconfig": kubeconfig})
    except json.JSONDecodeError as e:
        event.fail("Failed to parse kubeconfig: {}".format(str(e)))
    except Exception as e:
        event.fail("Failed to retrieve kubeconfig: {}".format(str(e)))


def apply_manifest(event: ops.ActionEvent):
    """Apply a user defined manifest with kubectl."""
    _, apply_path = tempfile.mkstemp(suffix=".json")
    try:
        manifest = json.loads(event.params["json"])
        with open(apply_path, "w") as manifest_file:
            json.dump(manifest, manifest_file)
        output = kubectl("apply", "-f", apply_path)

        event.set_results(
            {
                "summary": "Manifest applied.",
                "output": output.decode("utf-8"),
            }
        )
    except subprocess.CalledProcessError as e:
        event.fail(
            "kubectl failed with exit code {} and message: {}".format(e.returncode, e.output)
        )
    except json.JSONDecodeError as e:
        event.fail("Failed to parse JSON manifest: {}".format(str(e)))
    except Exception as e:
        event.fail("Failed to apply manifest: {}".format(str(e)))
    finally:
        os.unlink(apply_path)
