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

            if win_func.InternetOpenUrlA and win_func.InternetOpenUrlA.before.url then
                local url = win_func.InternetOpenUrlA.before.url:lower()
                if url == "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" then
                    return "Win32.WannaCry.DR"
                end
            end

        end
    end
    
    return status
end