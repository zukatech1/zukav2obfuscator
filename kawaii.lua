-- namegenerators/kawaii.lua
-- Generates UwU/weeb/furry flavored obfuscated names
-- Follows ZukaTech namegenerator conventions (util.shuffle, math.random)

local util = require("ZukaTech.util")

local seed       = 0
local offset     = 0
local call_count = 0

local kaomoji = {
    "uwu", "owo", "x3", "nya", "paw",
    "rawr", "blep", "mlem", "ewe", "uvu",
    "teehee", "hehe", "mwah", "boop", "snoot",
    "floof", "smorl", "bork", "meow", "woof"
}
local suffixes = {
    "chan", "kun", "senpai", "sama", "nyan",
    "pup", "kit", "floof", "bun", "paws",
    "chibi", "doki", "mochi", "neko", "kitsune",
    "puppers", "babey", "smol", "bbg", "cutie"
}
local prefixes = {
    "fluffy", "soft", "wiggly", "boopy", "snuggly",
    "pawsy", "meowy", "fuzzy", "cuddly", "derpy",
    "squishy", "tiny", "smoly", "cottony", "velvety",
    "silky", "dreamy", "blushy", "dainty", "precious"
}
local middles = {
    "wuv", "nyaa", "rawr", "mrow", "blep",
    "mlem", "hiss", "bork", "yip", "squeek",
    "murr", "churr", "trill", "chirp", "purr",
    "awoo", "yiff", "sniff", "nuzzle", "headpat"
}
local emotes = {
    "owo", "uwu", "xd", "xp", "owo",
    "teehee", "hehe", "hihi", "huhu", "hoho"
}

-- uwu-ify a base string
local function uwuify(s)
    s = s:gsub("r", "w")
    s = s:gsub("l", "w")
    s = s:gsub("R", "W")
    s = s:gsub("L", "W")
    s = s:gsub("th", "d")
    s = s:gsub("Th", "D")
    s = s:gsub("n([aeiou])", "ny%1")
    s = s:gsub("N([aeiou])", "Ny%1")
    s = s:gsub("ove", "uv")
    s = s:gsub("you", "yuu")
    s = s:gsub("the", "de")
    s = s:gsub("ck", "wk")
    s = s:gsub("ct", "wt")
    return s
end

local function hashVal(id)
    return (id * 2654435761 + seed * 0xBB38435) % 0xFFFFFFFF
end

local function kaoName(id)
    local v = hashVal(id)
    local kao = kaomoji[(v % #kaomoji) + 1]
    local suf = suffixes[((v + id) % #suffixes) + 1]
    local mid = middles[(v % #middles) + 1]
    return mid .. "_" .. kao .. "_" .. string.format("%x", v % 0xFFF) .. "_" .. suf
end

local function prefixName(id)
    local v = hashVal(id)
    local pre = prefixes[(v % #prefixes) + 1]
    local suf = suffixes[((v + id) % #suffixes) + 1]
    return uwuify(pre) .. "_" .. string.format("%x", v % 0xFFFF) .. "_" .. suf
end

local function midName(id)
    local v = hashVal(id)
    local mid = middles[(v % #middles) + 1]
    local kao = kaomoji[((v + id) % #kaomoji) + 1]
    return uwuify(mid) .. "_" .. uwuify(kao) .. "_" .. string.format("%x", v % 0xFF)
end

local function blendName(id)
    local v = hashVal(id)
    local pre = prefixes[(v % #prefixes) + 1]
    local mid = middles[((v + 1) % #middles) + 1]
    local suf = suffixes[((v + id) % #suffixes) + 1]
    return uwuify(pre) .. "_" .. uwuify(mid) .. "_" .. suf
end

local function emoteName(id)
    local v = hashVal(id)
    local emo = emotes[(v % #emotes) + 1]
    local suf = suffixes[((v + id) % #suffixes) + 1]
    local pre = prefixes[((v + 3) % #prefixes) + 1]
    return uwuify(emo) .. "_" .. uwuify(pre) .. "_" .. string.format("%x", v % 0xFF) .. "_" .. suf
end

local function generateName(id, scope)
    call_count = call_count + 1

    if call_count % 50 == 0 then
        seed = (seed * 1664525 + 1013904223) % 0xFFFFFFFF
    end

    id = id + offset
    local roll = hashVal(id) % 100

    if roll < 22 then
        return kaoName(id)
    elseif roll < 44 then
        return prefixName(id)
    elseif roll < 62 then
        return midName(id)
    elseif roll < 82 then
        return blendName(id)
    else
        return emoteName(id)
    end
end

local function prepare(ast)
    util.shuffle(kaomoji)
    util.shuffle(suffixes)
    util.shuffle(prefixes)
    util.shuffle(middles)
    util.shuffle(emotes)
    seed       = math.random(0, 0xFFFF)
    offset     = math.random(0, 9999)
    call_count = 0
end

return {
    generateName = generateName,
    prepare      = prepare,
}