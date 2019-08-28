import json
import os

# return (image_path, pid, sha_256)
def get_starter_details(report_directory):
    starter_json = report_directory + b"\\starter.json"
    if not os.path.exists(starter_json):
        return None, None, None
    with open(starter_json) as json_file:
        data = json.load(json_file)
        return data["image_path"], data["starter_pid"], data["sha_256"]
    return None, None, None

# returns json
def get_json_from_file(file_path):
    if not os.path.exists(file_path):
        return None, None, None
    with open(file_path) as json_file:
        data = json.load(json_file)
        return data