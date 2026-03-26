-- namegenerators/segaddr.lua
-- SegAddr — by Zuka
--
-- Names styled after memory segment addresses and register offsets.
-- Format: _[SEG][ADDR]_[OFF]_[TAG]
--
-- Examples: _3A9_k2F_B7   _B04_x7R_1C   _9Kf_3B2_mA
--
-- Why it destroys both human and AI analysis:
--   - Humans pattern-match to memory dumps / disassembly output
--     and mentally skip it as "not code"
--   - AI models trained on code see no semantic signal — no known
--     naming convention, no phonetic pattern, no structural hint
--   - Mixed case + digits + underscores at irregular positions
--     destroys LLM tokenization (each name becomes 3-5 tokens with
--     no relationship to each other)
--   - Looks like it came from a different tool entirely — reverser
--     wastes time trying to figure out what generated it
--   - Short enough to not bloat output significantly
--   - High entropy per character — no two names look related even
--     when they are sequential IDs

local util = require("ZukaTech.util")

-- Charset pools — deliberately mixed to destroy pattern recognition
-- Upper hex-ish chars: look like memory addresses
local HEX_UP  = { "0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F" }
-- Lower alphanum: looks like register names / offsets
local ALPHA_LO = { "a","b","c","d","e","f","g","h","i","j","k","m","n","p","q","r","s","t","v","x","y","z" }
-- Mixed: used for the "tag" segment — looks like a checksum
local MIXED   = { "0","1","2","3","4","5","6","7","8","9",
                  "A","B","C","D","F","K","N","R","X","Z",
                  "a","b","c","d","f","k","m","n","r","x" }

-- Segment length configs — each "block" between underscores
-- [min, max] chars per block
local BLOCK_CONFIGS = {
    { 2, 3 },   -- first block  e.g. "3A9" or "B0"
    { 1, 3 },   -- second block e.g. "k2F" or "x7"
    { 1, 2 },   -- third block  e.g. "B7" or "C"
}

-- Number of blocks per name — varies so names aren't all same length
-- 2 blocks = shorter,  3 blocks = longer
local BLOCK_COUNT_WEIGHTS = { 2, 2, 3, 3, 3 }  -- 3-block names are more common

local seed     = 0
local hexOrder  = {}
local loOrder   = {}
local mixOrder  = {}

-- Lua 5.1 compatible XOR (no bit library)
local function xor32(a, b)
    local result = 0
    local bit    = 1
    for _ = 1, 32 do
        if a % 2 ~= b % 2 then result = result + bit end
        a   = math.floor(a / 2)
        b   = math.floor(b / 2)
        bit = bit * 2
    end
    return result
end

-- Fast PRNG — avalanche hash style, deterministic from id+seed
local function prng(n)
    n = (n * 2654435761 + seed) % 0x100000000
    n = xor32(n, math.floor(n / 65536))
    n = (n * 2246822519) % 0x100000000
    n = xor32(n, math.floor(n / 4096))
    n = (n * 3266489917) % 0x100000000
    n = xor32(n, math.floor(n / 32768))
    return n
end

-- Pick a char from a pool using a shuffled order index
-- Guard against empty order table (called before prepare())
local function pick(pool, order, hash)
    if #order == 0 then
        return pool[(hash % #pool) + 1]
    end
    local idx = (hash % #order) + 1
    local val = pool[order[idx]]
    -- safety: if still nil fall back to direct index
    if val == nil then
        return pool[(hash % #pool) + 1]
    end
    return val
end

-- Generate one block of [len] chars
-- blockType: 1=hex-upper, 2=alpha-lower, 3=mixed
local function genBlock(id, blockIdx, len, blockType)
    local result = ""
    for i = 0, len - 1 do
        local h = prng(id * 97 + blockIdx * 31 + i * 13)
        if blockType == 1 then
            result = result .. pick(HEX_UP, hexOrder, h)
        elseif blockType == 2 then
            result = result .. pick(ALPHA_LO, loOrder, h)
        else
            result = result .. pick(MIXED, mixOrder, h)
        end
    end
    return result
end

-- Block type assignment — alternates to mix upper/lower/mixed
-- Creates the visual "segment_offset_tag" aesthetic
local BLOCK_TYPES = {
    [1] = { 1, 2, 3 },   -- hex, lower, mixed
    [2] = { 2, 1, 3 },   -- lower, hex, mixed
    [3] = { 1, 3, 2 },   -- hex, mixed, lower
    [4] = { 3, 1, 2 },   -- mixed, hex, lower
}

local function generateName(id, scope)
    -- Pick number of blocks for this name
    local bcw    = BLOCK_COUNT_WEIGHTS[(prng(id * 7) % #BLOCK_COUNT_WEIGHTS) + 1]
    local nBlocks = bcw

    -- Pick block type pattern — rotates per name so adjacent names look different
    local pattern = BLOCK_TYPES[(id % #BLOCK_TYPES) + 1]

    local name = "_"
    for b = 1, nBlocks do
        if b > 1 then name = name .. "_" end

        -- Pick length for this block
        local cfg = BLOCK_CONFIGS[b] or BLOCK_CONFIGS[#BLOCK_CONFIGS]
        local minL, maxL = cfg[1], cfg[2]
        local len = minL + (prng(id * 11 + b * 19) % (maxL - minL + 1))

        local btype = pattern[b] or 3
        name = name .. genBlock(id, b, len, btype)
    end

    return name
end

local function prepare(ast)
    seed = math.random(0, 0xFFFFFF)

    -- Shuffle index orders so each compilation run produces different names
    hexOrder = {}
    for i = 1, #HEX_UP do hexOrder[i] = i end
    util.shuffle(hexOrder)

    loOrder = {}
    for i = 1, #ALPHA_LO do loOrder[i] = i end
    util.shuffle(loOrder)

    mixOrder = {}
    for i = 1, #MIXED do mixOrder[i] = i end
    util.shuffle(mixOrder)
end

return {
    generateName = generateName,
    prepare      = prepare,
}
