-- steps/Cuteify.lua
-- Obfuscation Step: Cuteify
--
-- Ironically cute, unironically hard to reverse.
-- Three layered hardening techniques on top of uwu transformation:
--
-- Layer 1 — UwU substitution:
--   Applies character-level substitutions (r->w, l->w, th->d, n+vowel->ny etc.)
--   Configurable intensity 1-3.
--
-- Layer 2 — String concat splitting:
--   Breaks transformed strings into concat fragments at random split points.
--   "waifu_uwu" becomes ("wai" .. "fu" .. "_uwu") in the AST.
--   Makes reconstruction tedious — decompilers show the tree, not the value.
--
-- Layer 3 — Homoglyph injection:
--   Injects visually identical unicode lookalikes into strings.
--   Breaks ctrl+F, grep, string.find, and == comparison silently.
--   Uses only codepoints that Lua 5.1 treats as valid string bytes.
--
-- Layer 4 — Decoy string injection:
--   Injects fake dead-local kawaii strings into blocks, polluting the
--   string pool with plausible-looking noise that never gets used.
--
-- Safe guarantees:
--   * Skips strings that look like require paths (contain . / \)
--   * Skips strings under 3 chars
--   * Skips purely numeric strings
--   * Decoys are always dead locals — never affect control flow
--   * Fully Lua 5.1 / pipeline compatible

local Step     = require("ZukaTech.step")
local Ast      = require("ZukaTech.ast")
local Scope    = require("ZukaTech.scope")
local visitast = require("ZukaTech.visitast")

local AstKind  = Ast.AstKind

local Cuteify             = Step:extend()
Cuteify.Name              = "Cuteify"
Cuteify.Description       = "UwU string transformation with concat splitting, homoglyph injection, and decoy string flooding"

Cuteify.SettingsDescriptor = {
    Threshold = {
        type    = "number",
        default = 0.75,
        min     = 0.0,
        max     = 1.0,
    },
    Intensity = {
        type    = "number",
        default = 2,
        min     = 1,
        max     = 3,
    },
    SplitStrings = {
        type    = "boolean",
        default = true,
    },
    HomoglyphInject = {
        type    = "boolean",
        default = true,
    },
    DecoyCount = {
        type    = "number",
        default = 2,
        min     = 0,
        max     = 8,
    },
    DecoyThreshold = {
        type    = "number",
        default = 0.6,
        min     = 0.0,
        max     = 1.0,
    },
}

function Cuteify:init() end

-- ─── Homoglyph table ─────────────────────────────────────────────────────────
-- Maps ASCII chars to visually near-identical unicode lookalikes.
-- All are valid single-codepoint utf8 sequences Lua 5.1 passes as string bytes.
local homoglyphs = {
    a = "\xC3\xA0",  -- à  (U+00E0)
    e = "\xC3\xA9",  -- é  (U+00E9)
    i = "\xC3\xAC",  -- ì  (U+00EC)
    o = "\xC3\xB2",  -- ò  (U+00F2)
    u = "\xC3\xBC",  -- ü  (U+00FC)
    n = "\xC3\xB1",  -- ñ  (U+00F1)
    c = "\xC3\xA7",  -- ç  (U+00E7)
}
local homoglyph_keys = {"a","e","i","o","u","n","c"}

-- ─── Kawaii pools ─────────────────────────────────────────────────────────────
local decoy_pool = {
    "wuv_nya", "owo_bun", "blep_kit", "rawr_paw", "mlem_chan",
    "floof_uwu", "purr_kun", "nyaa_sama", "bork_nyan", "squeek_chibi",
    "smorl_doki", "murr_floof", "awoo_pup", "yip_mochi", "chirp_bbg"
}

local kawaii_suffixes = {
    "_uwu", "_owo", "_nya", "_x3", "_rawr",
    "_blep", "_paw", "_bun", "_floof", "_mlem"
}

-- ─── Helpers ─────────────────────────────────────────────────────────────────

local function isSensitive(val)
    if val:find("[%.%/\\]")  then return true end
    if #val <= 2             then return true end
    if val:match("^%d+$")   then return true end
    return false
end

local function uwuify(s, intensity)
    s = s:gsub("r", "w"):gsub("l", "w"):gsub("R", "W"):gsub("L", "W")
    if intensity >= 2 then
        s = s:gsub("th", "d"):gsub("Th", "D"):gsub("TH", "D")
        s = s:gsub("n([aeiou])", "ny%1")
        s = s:gsub("N([aeiou])", "Ny%1")
    end
    if intensity >= 3 then
        s = s:gsub("ove", "uv"):gsub("you", "yuu")
        s = s:gsub("the", "de"):gsub("ck",  "wk"):gsub("ct", "wt")
    end
    return s
end

-- Inject homoglyph substitutions at random positions
local function injectHomoglyphs(s)
    if #s < 3 then return s end
    local result = {}
    for i = 1, #s do
        local ch = s:sub(i, i)
        local glyph = homoglyphs[ch]
        if glyph and math.random() > 0.55 then
            result[#result + 1] = glyph
        else
            result[#result + 1] = ch
        end
    end
    return table.concat(result)
end

-- Split a string into N random fragments, return as StrCatExpression chain
local function splitToConcat(s)
    if #s <= 3 then
        return Ast.StringExpression(s)
    end

    -- Pick 1-3 split points
    local splits = math.random(1, math.min(3, math.floor(#s / 2)))
    local points = {}
    for _ = 1, splits do
        table.insert(points, math.random(1, #s - 1))
    end
    table.sort(points)

    -- Deduplicate points
    local unique = {}
    local last = -1
    for _, p in ipairs(points) do
        if p ~= last then
            unique[#unique + 1] = p
            last = p
        end
    end

    -- Build fragments
    local fragments = {}
    local prev = 0
    for _, p in ipairs(unique) do
        if p > prev then
            fragments[#fragments + 1] = s:sub(prev + 1, p)
            prev = p
        end
    end
    fragments[#fragments + 1] = s:sub(prev + 1)

    -- Build right-associative StrCatExpression chain
    local node = Ast.StringExpression(fragments[#fragments])
    for i = #fragments - 1, 1, -1 do
        node = Ast.StrCatExpression(Ast.StringExpression(fragments[i]), node)
    end
    return node
end

-- Build a dead local that holds a fake kawaii string:
--   local _v = "wuv_nya" .. "x3" etc.
local function buildDecoy(blockScope, intensity, doSplit, doHomoglyph)
    local jScope = Scope:new(blockScope)
    local jId    = jScope:addVariable()

    local base = decoy_pool[math.random(#decoy_pool)]
    local suf  = kawaii_suffixes[math.random(#kawaii_suffixes)]
    local val  = uwuify(base .. suf, intensity)

    if doHomoglyph then
        val = injectHomoglyphs(val)
    end

    local valNode
    if doSplit then
        valNode = splitToConcat(val)
    else
        valNode = Ast.StringExpression(val)
    end

    -- local _v = <val>; _v = nil
    return {
        Ast.LocalVariableDeclaration(jScope, { jId }, { valNode }),
        Ast.AssignmentStatement(
            { Ast.AssignmentVariable(jScope, jId) },
            { Ast.NilExpression() }
        ),
    }
end

-- ─── Apply ────────────────────────────────────────────────────────────────────

function Cuteify:apply(ast)
    local intensity      = self.Intensity
    local threshold      = self.Threshold
    local doSplit        = self.SplitStrings
    local doHomoglyph    = self.HomoglyphInject
    local decoyCount     = self.DecoyCount
    local decoyThreshold = self.DecoyThreshold

    -- Pass 1: transform existing StringExpression nodes
    visitast(ast, nil, function(node, data)
        if node.kind ~= AstKind.StringExpression then return end
        if math.random() > threshold then return end

        local val = node.value
        if type(val) ~= "string" then return end
        if isSensitive(val) then return end

        local transformed = uwuify(val, intensity)

        -- Append a kawaii suffix occasionally
        if math.random() > 0.5 then
            transformed = transformed .. kawaii_suffixes[math.random(#kawaii_suffixes)]
        end

        if doHomoglyph then
            transformed = injectHomoglyphs(transformed)
        end

        -- If splitting, we need to replace this node in its parent.
        -- We do this by mutating node fields to become a StrCatExpression.
        if doSplit and #transformed > 3 then
            local concat = splitToConcat(transformed)
            -- Mutate node in-place to become the concat node
            node.kind  = concat.kind
            node.value = nil
            for k, v in pairs(concat) do
                node[k] = v
            end
        else
            node.value = transformed
        end
    end)

    -- Pass 2: inject decoy strings into blocks
    if decoyCount > 0 then
        visitast(ast, nil, function(node, data)
            if node.kind ~= AstKind.Block then return end
            if math.random() > decoyThreshold then return end
            if #node.statements == 0 then return end

            -- Don't inject after return/break
            local maxInsert = #node.statements
            for i = #node.statements, 1, -1 do
                local k = node.statements[i].kind
                if k == AstKind.ReturnStatement or k == AstKind.BreakStatement then
                    maxInsert = i - 1
                else break end
            end
            if maxInsert < 0 then return end

            for _ = 1, decoyCount do
                local pos   = math.random(1, maxInsert + 1)
                local stmts = buildDecoy(node.scope, intensity, doSplit, doHomoglyph)
                for offset, stmt in ipairs(stmts) do
                    table.insert(node.statements, pos + offset - 1, stmt)
                end
                maxInsert = maxInsert + #stmts
            end
        end)
    end
end

return Cuteify