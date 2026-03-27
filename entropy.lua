-- namegenerators/entropy.lua
-- High-entropy per-compile names using 4 strategies:
--   hash-based, dictionary mashup, homoglyph-injected, pure entropy
-- All names are deterministic within a build (same id = same name)

local util = require("ZukaTech.util")

-- ── internal state ────────────────────────────────────────────────────────────
local seed   = 0
local offset = 0

-- ── homoglyph map (Cyrillic lookalikes for Latin chars) ───────────────────────
local homoglyphs = {
    a = "\xD0\xB0", -- а (Cyrillic)
    e = "\xD0\xB5", -- е
    o = "\xD0\xBE", -- о
    p = "\xD1\x80", -- р
    c = "\xD1\x81", -- с
    x = "\xD1\x85", -- х
}

-- ── word fragments for mashup names ──────────────────────────────────────────
local prefixes = {"get","set","do","run","load","init","proc","buf","ctx","ref"}
local suffixes = {"Data","Val","Ref","Ptr","Obj","Buf","Ctx","Res","Tab","Map"}

-- ── charset for pure entropy names ───────────────────────────────────────────
local charset = util.chararray("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

-- ── helpers ───────────────────────────────────────────────────────────────────
local function hashVal(id)
    -- cheap but non-sequential hash, stays within u32
    return (id * 2654435761 + seed * 0xBB38435) % 0xFFFFFFFF
end

local function hashName(id)
    local v = hashVal(id)
    return string.format("_%x", v)
end

local function mashupName(id)
    local v   = hashVal(id)
    local pre = prefixes[(v % #prefixes) + 1]
    local suf = suffixes[((v + id) % #suffixes) + 1]
    local mid = string.format("%x", v % 0xFF)
    return pre .. mid .. suf
end

local function applyHomoglyphs(name, id)
    -- use id as a per-name decision seed so substitution is deterministic
    local result = ""
    local roll   = hashVal(id)
    for i = 1, #name do
        local char = name:sub(i, i)
        roll = (roll * 6364136223846793005 + 1442695040888963407) % 0xFFFFFFFF
        if homoglyphs[char] and (roll % 100) < 40 then
            result = result .. homoglyphs[char]
        else
            result = result .. char
        end
    end
    return result
end

local function entropyName(id, len)
    len = len or (6 + (hashVal(id) % 8)) -- 6..13 chars
    local name = "_"
    local v    = hashVal(id)
    for i = 1, len do
        v    = (v * 6364136223846793005 + 1442695040888963407) % 0xFFFFFFFF
        name = name .. charset[(v % #charset) + 1]
    end
    return name
end

-- ── public API ────────────────────────────────────────────────────────────────
local function generateName(id, scope)
    id = id + offset
    local roll = hashVal(id) % 100

    if roll < 25 then
        return hashName(id)
    elseif roll < 50 then
        return applyHomoglyphs(mashupName(id), id)
    elseif roll < 75 then
        return entropyName(id)
    else
        -- hybrid: hash prefix + short entropy tail
        return hashName(id) .. entropyName(id, 4)
    end
end

local function prepare(ast)
    util.shuffle(prefixes)
    util.shuffle(suffixes)
    util.shuffle(charset)
    seed   = math.random(0, 0xFFFF)
    offset = math.random(0, 9999)
end

return {
    generateName = generateName,
    prepare      = prepare,
}