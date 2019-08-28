-- json = require "json"
utils = require "utils"

-- detection logic
function check(report_directory)

    local status = "CLEAN"

    -- open the first json file and read content
    local first_dynamic = utils.get_first_process_json(report_directory)
    local first_static = utils.get_first_static(report_directory)

-- 
--  your code starts from here
-- 
    -- static information
    local is_x86 = false
    if first_static ~= nil then
        is_x86 = first_static.generic.is_x86
    end

    -- dynamic information
    if first_dynamic ~= nil then
        -- enumerate json
        for index, win_func in pairs(first_dynamic) do

            -- get information from a call, e.g. if the call is NtCreateUserProcess
            if win_func.NtCreateUserProcess then
                -- Get a PID of a new process, with PID we can enumerate calls from a new process
                if win_func.NtCreateUserProcess.success == true then
                    local target_PID = win_func.NtCreateUserProcess.after.proc_id
                    local decoded_json = utils.get_json_pid(report_directory, target_PID)
                    if not decoded_json.empty then
                        -- enumerate a json of the child process
                    end
                end

                -- and check the new process parameters 
                if win_func.NtCreateUserProcess.before.image_path ~= nil then
                    if win_func.NtCreateUserProcess.before.image_path:find("whoami") then
                        return "WHOAMI!EXE"
                    end
                end
            end

            -- other check for reg key creation
            if win_func.NtCreateKey and win_func.NtCreateKey.success == true then
            	if win_func.NtCreateKey.before.key_path:find("malicious_key_for_dr_semu") then
            		return "Dr.Semu!TEST"
            	end
            end

        end
    end
    
    return status
end