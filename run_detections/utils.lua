-- put under current_dir/lua

json = require "json"

local utils = { _version = "0.1.0" }

function utils.read_content(json_path)
    file = io.open(json_path, "r")
    io.input(file)
    content = io.read("*all")
    io.close(file)
    return content
end

function utils.get_json_from_path(json_path)
    local content = utils.read_content(json_path)
    local decoded = json.decode(content)
    return decoded
end

function utils.get_json_pid(report_directory, pid)
    local json_file = report_directory .. "\\" .. pid .. ".json"
    local decoded = utils.get_json_from_path(json_file)
    return decoded
end

function utils.get_first_process_json(report_directory)
	local starter_json = report_directory .. "\\" .. "starter.json"
    local decoded_starer_json = utils.get_json_from_path(starter_json)
    if decoded_starer_json.empty then
        return nil
    end
    local starter_path = decoded_starer_json.image_path
    local starter_pid = decoded_starer_json.starter_pid
    if starter_path == nil or starter_pid == nil then
        return nil
    end

    -- starter process
    local first_decoded_dynamic = utils.get_json_pid(report_directory, starter_pid)
    if first_decoded_dynamic.empty then
        return nil
    end

    return first_decoded_dynamic
end

function utils.get_first_static(report_directory)
	local starter_json = report_directory .. "\\" .. "starter.json"
    local decoded_starer_json = utils.get_json_from_path(starter_json)
    if decoded_starer_json.empty then
        return nil
    end
    local sha_256 = decoded_starer_json.sha_256
    local static_decoded = utils.get_json_from_path(report_directory .. "\\" .. sha_256 .. ".json")
    return static_decoded
end

return utils