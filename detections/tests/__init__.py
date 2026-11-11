# Marks detections/tests/ as importable, so that both discovery forms work:
#   python3 -B -m unittest discover -s detections/tests           (the documented form)
#   python3 -B -m unittest discover -s detections/tests -t .
# The gates under detections/ are plain scripts, not a package: the tests never import
# them. They run each gate as a child process in a copy of the repository (gatelib.py).
