import json
import os

import dr_semu_utils

# don't forget to add module names into py_imports.config file

def check(report_directory):
    
    image_path, pid, sha_256 = dr_semu_utils.get_starter_details(report_directory)
    static_info = dr_semu_utils.get_json_from_file(report_directory + b"\\" + sha_256.encode() + b".json")
    dynamic_info = dr_semu_utils.get_json_from_file(report_directory + b"\\" + str(pid).encode() + b".json")

    # code here
    verdict = b"CLEAN"

    for win_func in dynamic_info:
        if "NtCreateUserProcess" in win_func:
            image_path = win_func["NtCreateUserProcess"]["before"]["image_path"]
            if image_path.lower().endswith("drsemu_eicar.exe"):
                return b"Win32.EICAR.Dr"

    return verdict


if __name__ == "__main__":
    pass
