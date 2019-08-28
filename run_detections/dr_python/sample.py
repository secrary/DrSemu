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

def check(report_directory):
    
    image_path, pid, sha_256 = get_starter_details(report_directory)
    static_info = get_json_from_file(report_directory + b"\\" + sha_256.encode() + b".json")
    dynamic_info = get_json_from_file(report_directory + b"\\" + str(pid).encode() + b".json")

    # code here
    verdict = b"CLEAN"

    for win_func in dynamic_info:
        if "NtCreateUserProcess" in win_func:
            image_path = win_func["NtCreateUserProcess"]["before"]["image_path"]
            if image_path.endswith("drsemu_eicar.exe"):
                return b"Win32.EICAR.Dr"

    return verdict


if __name__ == "__main__":
    pass
