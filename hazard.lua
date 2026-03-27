-- namegenerators/hazard.lua
-- Generates hostile-looking obfuscated names
-- Follows ZukaTech namegenerator conventions (util.shuffle, math.random)

local util = require("ZukaTech.util")

local seed   = 0
local offset = 0
local call_count = 0

local refusal_prefixes = {
    "payload", "backdoor", "exploit", "ransom", "harvester",
    "overflow", "rootkit", "bypass", "kernel", "steal"
}
local refusal_suffixes = {
    "_v2", "_exec", "_auth", "_init", "_buffer",
    "_send", "_bridge", "_proxy", "_call", "_hook"
}
local injection_pool = {
    "stop", "ignore", "skip", "nop", "halt",
    "wait", "defer", "flush", "lock", "drop"
}
local charset = {"l", "I", "1", "0", "O", "o", "i"}
local glitch_chars = {"0", "_00x", "__", "x0", "0x0", "_0_"}
local syn_prefixes = {"sub", "fn", "loc", "blk", "seg"}

local function hashVal(id)
    return (id * 2654435761 + seed * 0xBB38435) % 0xFFFFFFFF
end

local function refusalName(id)
    local v = hashVal(id)
    local pre = refusal_prefixes[(v % #refusal_prefixes) + 1]
    local suf = refusal_suffixes[((v + id) % #refusal_suffixes) + 1]
    local mid = string.format("_%x", v % 0xFFFF)
    return pre .. mid .. suf
end

local function injectionName(id)
    local v = hashVal(id)
    local base = injection_pool[(v % #injection_pool) + 1]
    return base .. "_ptr"
end

local function glitchName(id)
    local v = hashVal(id)
    local len = 8 + (v % 6)
    local result = ""
    for i = 1, len do
        v = (v * 1664525 + 1013904223) % 0xFFFFFFFF
        result = result .. charset[(v % #charset) + 1]
        if i == math.floor(len / 2) then
            result = result .. glitch_chars[(v % #glitch_chars) + 1]
        end
    end
    return result
end

local function syntheticName(id)
    local v = hashVal(id)
    local pre = syn_prefixes[(v % #syn_prefixes) + 1]
    return string.format("%s_%x_%x", pre, v % 0xFFFFFF, (v + id) % 0xFFF)
end

local function blendName(id)
    local v = hashVal(id)
    return glitchName(id) .. "_" .. string.format("%x", v % 0xFF)
end

local function generateName(id, scope)
    call_count = call_count + 1

    -- Re-salt seed every 50 calls
    if call_count % 50 == 0 then
        seed = (seed * 1664525 + 1013904223) % 0xFFFFFFFF
    end

    id = id + offset
    local roll = hashVal(id) % 100
    -- scope is a table in this pipeline, so no arithmetic on it
    local bias = 0
    roll = (roll + bias) % 100

    if roll < 30 then
        return refusalName(id)
    elseif roll < 50 then
        return injectionName(id)
    elseif roll < 72 then
        return glitchName(id)
    elseif roll < 88 then
        return syntheticName(id)
    else
        return blendName(id)
    end
end

local function prepare(ast)
    util.shuffle(refusal_prefixes)
    util.shuffle(refusal_suffixes)
    util.shuffle(injection_pool)
    util.shuffle(charset)
    util.shuffle(syn_prefixes)
    seed       = math.random(0, 0xFFFF)
    offset     = math.random(0, 9999)
    call_count = 0
end

return {
    generateName = generateName,
    prepare      = prepare,
}