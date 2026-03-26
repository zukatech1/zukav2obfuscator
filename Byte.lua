-- BytecodeCompiler.lua
-- Compiles a Prometheus AST into a custom binary bytecode format and emits
-- a self-contained Lua 5.1-compatible VM executor.
--
-- Design:
--   • Opcode table is randomized per-compilation — same instruction maps to a
--     different byte every run, defeating opcode-pattern scanners.
--   • Bytecode is stored as a length-prefixed binary string; no source is present.
--   • The emitted VM is a register-based interpreter (similar to PUC Lua 5.1)
--     with 256 virtual registers and a value stack for calls/returns.
--   • Constants (numbers, strings, booleans, nil) live in a per-proto const table.
--   • Upvalues and closures are supported via UpvalueCell objects.
--   • Instructions are 4 bytes: [OP:1][A:1][B:1][C:1]  (some use Bx = B<<8|C)
--
-- Instruction set (internal names → randomized byte at emit time):
--   LOADK    A Bx    R(A) = K(Bx)
--   LOADNIL  A B     R(A..B) = nil
--   LOADBOOL A B C   R(A) = (bool)B; if C then PC++
--   MOVE     A B     R(A) = R(B)
--   GETUPVAL A B     R(A) = UpValue[B]
--   SETUPVAL A B     UpValue[B] = R(A)
--   GETTABUP A B C   R(A) = UpValue[B][RK(C)]    (global read: _ENV[K])
--   SETTABUP A B C   UpValue[A][RK(B)] = RK(C)   (global write)
--   GETTABLE A B C   R(A) = R(B)[RK(C)]
--   SETTABLE A B C   R(A)[RK(B)] = RK(C)
--   NEWTABLE A B C   R(A) = {}
--   SETLIST  A B C   R(A)[C*FPF+i] = R(A+i) for 1<=i<=B
--   ADD      A B C   R(A) = RK(B) + RK(C)
--   SUB      A B C   R(A) = RK(B) - RK(C)
--   MUL      A B C   R(A) = RK(B) * RK(C)
--   DIV      A B C   R(A) = RK(B) / RK(C)
--   MOD      A B C   R(A) = RK(B) % RK(C)
--   POW      A B C   R(A) = RK(B) ^ RK(C)
--   UNM      A B     R(A) = -R(B)
--   NOT      A B     R(A) = not R(B)
--   LEN      A B     R(A) = #R(B)
--   CONCAT   A B C   R(A) = R(B)..R(B+1)..…..R(C)
--   JMP      A sBx   PC += sBx  (A = close-upval hint, unused here)
--   EQ       A B C   if (RK(B)==RK(C)) ~= A then PC++
--   LT       A B C   if (RK(B)< RK(C)) ~= A then PC++
--   LE       A B C   if (RK(B)<=RK(C)) ~= A then PC++
--   TEST     A C     if R(A) ~= C then PC++
--   TESTSET  A B C   if R(B) ~= C then PC++ else R(A)=R(B)
--   CALL     A B C   R(A)..R(A+C-2) = R(A)(R(A+1)..R(A+B-1))
--   TAILCALL A B C   return R(A)(R(A+1)..R(A+B-1))
--   RETURN   A B     return R(A)..R(A+B-2)
--   FORLOOP  A sBx   R(A)+=R(A+2); if R(A)<=R(A+1) then PC+=sBx, R(A+3)=R(A)
--   FORPREP  A sBx   R(A)-=R(A+2); PC+=sBx
--   TFORLOOP A C     R(A+3)..R(A+2+C) = R(A)(R(A+1),R(A+2)); if R(A+3) then R(A+2)=R(A+3), PC-=1
--   CLOSURE  A Bx    R(A) = closure(Proto[Bx])
--   VARARG   A B     R(A)..R(A+B-2) = vararg
--   SELF     A B C   R(A+1)=R(B); R(A)=R(B)[RK(C)]

local Ast     = require("prometheus.ast")
local AstKind = Ast.AstKind
local Scope   = require("prometheus.scope")
local visitast = require("prometheus.visitast")

local BytecodeCompiler = {}
BytecodeCompiler.__index = BytecodeCompiler

-- ─── opcode enum (stable internal IDs) ───────────────────────────────────────
local OP = {
    LOADK    = 0,  LOADNIL  = 1,  LOADBOOL = 2,  MOVE     = 3,
    GETUPVAL = 4,  SETUPVAL = 5,  GETTABUP = 6,  SETTABUP = 7,
    GETTABLE = 8,  SETTABLE = 9,  NEWTABLE = 10, SETLIST  = 11,
    ADD      = 12, SUB      = 13, MUL      = 14, DIV      = 15,
    MOD      = 16, POW      = 17, UNM      = 18, NOT      = 19,
    LEN      = 20, CONCAT   = 21, JMP      = 22, EQ       = 23,
    LT       = 24, LE       = 25, TEST     = 26, TESTSET  = 27,
    CALL     = 28, TAILCALL = 29, RETURN   = 30, FORLOOP  = 31,
    FORPREP  = 32, TFORLOOP = 33, CLOSURE  = 34, VARARG   = 35,
    SELF     = 36,
}
local OP_COUNT = 37
local FPF = 50  -- fields-per-flush for SETLIST

-- ─── constructor ─────────────────────────────────────────────────────────────
function BytecodeCompiler:new()
    local o = setmetatable({}, self)
    -- Build randomized opcode permutation: internal_id -> wire_byte
    local perm = {}
    for i = 0, 255 do perm[i] = i end
    -- Fisher-Yates on 0..255, then take first OP_COUNT slots
    for i = 255, 1, -1 do
        local j = math.random(0, i)
        perm[i], perm[j] = perm[j], perm[i]
    end
    o.opmap = {}        -- internal -> wire
    o.inv_opmap = {}    -- wire -> internal (for the VM template)
    for id = 0, OP_COUNT - 1 do
        o.opmap[id]        = perm[id]
        o.inv_opmap[perm[id]] = id
    end
    return o
end

-- ─── Proto: one function prototype ───────────────────────────────────────────
local Proto = {}
Proto.__index = Proto

function Proto:new(parent)
    return setmetatable({
        code      = {},   -- list of {op, a, b, c}  (internal op IDs)
        consts    = {},   -- list of values
        constIdx  = {},   -- value -> 1-based index (strings/numbers/bools)
        protos    = {},   -- child Proto objects
        upvals    = {},   -- list of {name, instack, idx}
        upvalIdx  = {},   -- name -> 1-based index
        numparams = 0,
        is_vararg = false,
        maxstack  = 2,
        parent    = parent,
        -- register allocator
        nextReg   = 0,
        -- local variable name -> register
        locals    = {},
        localStack = {},  -- stack of {name, reg} for scoping
    }, self)
end

function Proto:emit(op, a, b, c)
    table.insert(self.code, { op = op, a = a or 0, b = b or 0, c = c or 0 })
    return #self.code  -- 1-based PC of emitted instruction
end

function Proto:patch(pc, field, val)
    self.code[pc][field] = val
end

-- Returns current PC (next instruction index)
function Proto:pc()
    return #self.code + 1
end

function Proto:allocReg()
    local r = self.nextReg
    self.nextReg = self.nextReg + 1
    if self.nextReg > self.maxstack then
        self.maxstack = self.nextReg
    end
    return r
end

function Proto:freeReg(n)
    n = n or 1
    self.nextReg = self.nextReg - n
end

function Proto:addConst(val)
    local key = type(val) .. "|" .. tostring(val)
    if self.constIdx[key] then return self.constIdx[key] - 1 end  -- 0-based
    table.insert(self.consts, val)
    self.constIdx[key] = #self.consts
    return #self.consts - 1  -- 0-based
end

-- RK encoding: constants >= 256 encoded as 256+constIdx
local RK_BIAS = 256
function Proto:rk(val)
    return RK_BIAS + self:addConst(val)
end

function Proto:addUpval(name, instack, idx)
    if self.upvalIdx[name] then return self.upvalIdx[name] - 1 end
    table.insert(self.upvals, { name = name, instack = instack, idx = idx })
    self.upvalIdx[name] = #self.upvals
    return #self.upvals - 1  -- 0-based
end

function Proto:pushLocal(name)
    local r = self:allocReg()
    self.locals[name] = r
    table.insert(self.localStack, { name = name, reg = r, saved = self.locals[name] })
    return r
end

function Proto:popLocals(count)
    for i = 1, count do
        local entry = table.remove(self.localStack)
        if entry then
            self.locals[entry.name] = entry.saved
            self:freeReg()
        end
    end
end

function Proto:resolveLocal(name)
    return self.locals[name]  -- register or nil
end

-- ─── serializer: proto -> binary string ──────────────────────────────────────
local function encodeU8(n)
    return string.char(n % 256)
end

local function encodeU16(n)
    n = n % 65536
    return string.char(n % 256, math.floor(n / 256))
end

local function encodeU32(n)
    n = n % (2^32)
    local b0 = n % 256
    local b1 = math.floor(n / 256)   % 256
    local b2 = math.floor(n / 65536) % 256
    local b3 = math.floor(n / 16777216) % 256
    return string.char(b0, b1, b2, b3)
end

local function encodeDouble(v)
    -- Encode IEEE 754 double as 8 bytes (little-endian)
    -- Pure-Lua implementation for Lua 5.1 compatibility
    if v == 0 then return string.rep("\0", 8) end
    local sign = 0
    if v < 0 then sign = 1; v = -v end
    if v ~= v then  -- NaN
        return string.char(0,0,0,0,0,0,0xF8,0x7F)
    end
    if v == math.huge then
        return string.char(0,0,0,0,0,0,0xF0, sign==1 and 0xFF or 0x7F)
    end
    local exp = 0
    if v >= 1 then
        while v >= 2 do v = v / 2; exp = exp + 1 end
    else
        while v < 1 do v = v * 2; exp = exp - 1 end
    end
    exp = exp + 1023  -- bias
    v = v - 1  -- remove implicit leading 1
    -- mantissa: 52 bits
    local mantissa = {}
    for i = 1, 52 do
        v = v * 2
        if v >= 1 then
            mantissa[i] = 1
            v = v - 1
        else
            mantissa[i] = 0
        end
    end
    -- pack: [sign:1][exp:11][mantissa:52]
    local bytes = {0,0,0,0,0,0,0,0}
    -- byte 7 (index 8, MSB): sign + top 7 bits of exp
    bytes[8] = sign * 128 + math.floor(exp / 16)
    -- byte 6 (index 7): low 4 bits of exp + top 4 bits of mantissa
    bytes[7] = (exp % 16) * 16 + mantissa[1]*8 + mantissa[2]*4 + mantissa[3]*2 + mantissa[4]
    -- bytes 5..1: remaining 48 mantissa bits, 8 per byte
    for b = 6, 1, -1 do
        local base = (6 - b) * 8 + 5
        local val = 0
        for bit = 0, 7 do
            val = val + (mantissa[base + bit] or 0) * (2^(7-bit))
        end
        bytes[b] = val
    end
    local out = {}
    for i = 1, 8 do out[i] = string.char(bytes[i]) end
    return table.concat(out)
end

local function encodeString(s)
    -- length-prefixed: U32 len + bytes
    return encodeU32(#s) .. s
end

local function serializeProto(proto, opmap)
    local parts = {}

    -- Header
    table.insert(parts, encodeU8(proto.numparams))
    table.insert(parts, encodeU8(proto.is_vararg and 1 or 0))
    table.insert(parts, encodeU8(proto.maxstack))

    -- Instructions
    table.insert(parts, encodeU32(#proto.code))
    for _, ins in ipairs(proto.code) do
        local wire = opmap[ins.op]
        table.insert(parts, encodeU8(wire))
        table.insert(parts, encodeU8(ins.a % 256))
        -- B and C packed: B in bits 8..15, C in 0..7 of a 16-bit Bx
        local bx = (ins.b % 256) * 256 + (ins.c % 256)
        table.insert(parts, encodeU16(bx))
    end

    -- Constants
    table.insert(parts, encodeU32(#proto.consts))
    for _, v in ipairs(proto.consts) do
        local t = type(v)
        if t == "nil" then
            table.insert(parts, encodeU8(0))
        elseif t == "boolean" then
            table.insert(parts, encodeU8(1))
            table.insert(parts, encodeU8(v and 1 or 0))
        elseif t == "number" then
            table.insert(parts, encodeU8(2))
            table.insert(parts, encodeDouble(v))
        elseif t == "string" then
            table.insert(parts, encodeU8(3))
            table.insert(parts, encodeString(v))
        end
    end

    -- Upvalues
    table.insert(parts, encodeU32(#proto.upvals))
    for _, uv in ipairs(proto.upvals) do
        table.insert(parts, encodeU8(uv.instack and 1 or 0))
        table.insert(parts, encodeU8(uv.idx))
    end

    -- Child protos
    table.insert(parts, encodeU32(#proto.protos))
    for _, child in ipairs(proto.protos) do
        table.insert(parts, serializeProto(child, opmap))
    end

    return table.concat(parts)
end

-- ─── VM template (emitted as Lua source) ─────────────────────────────────────
-- The inv_opmap is baked in as a lookup table literal so the VM can dispatch.
local function buildVMSource(bytecodeB64, inv_opmap)
    -- Serialize inv_opmap as a Lua table literal {[wire]=internal, ...}
    local mapEntries = {}
    for wire, internal in pairs(inv_opmap) do
        table.insert(mapEntries, string.format("[%d]=%d", wire, internal))
    end
    local mapLiteral = "{" .. table.concat(mapEntries, ",") .. "}"

    -- Base64 decoder + VM, all in one self-contained chunk
    return string.format([[
local _bc_b64 = %q
local _opmap  = %s

-- Base64 decode
local function _b64decode(s)
    local lk = {}
    local cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for i = 1, #cs do lk[cs:sub(i,i)] = i-1 end
    local out, v, c = {}, 0, 0
    for ch in s:gmatch(".") do
        if ch == "=" then break end
        local d = lk[ch]
        if d then
            v = v * 64 + d; c = c + 1
            if c == 4 then
                out[#out+1] = string.char(math.floor(v/65536)%256,
                                          math.floor(v/256)%256,
                                          v%%256)
                v, c = 0, 0
            end
        end
    end
    if c == 3 then
        out[#out+1] = string.char(math.floor(v/1024)%%256, math.floor(v/4)%%256)
    elseif c == 2 then
        out[#out+1] = string.char(math.floor(v/16)%%256)
    end
    return table.concat(out)
end

local _bc = _b64decode(_bc_b64)

-- Binary reader
local function _reader(s)
    local pos = 1
    local function ru8()  local v=s:byte(pos); pos=pos+1; return v end
    local function ru16()
        local lo=s:byte(pos); local hi=s:byte(pos+1); pos=pos+2
        return hi*256+lo
    end
    local function ru32()
        local b0,b1,b2,b3=s:byte(pos,pos+3); pos=pos+4
        return b0 + b1*256 + b2*65536 + b3*16777216
    end
    local function rstr()
        local l=ru32(); local v=s:sub(pos,pos+l-1); pos=pos+l; return v
    end
    local function rdouble()
        local bytes={s:byte(pos,pos+7)}; pos=pos+8
        -- Reconstruct IEEE 754 double
        local sign = math.floor(bytes[8]/128)
        local exp  = (bytes[8]%%128)*16 + math.floor(bytes[7]/16)
        if exp == 0 then return 0 end
        if exp == 2047 then return sign==1 and -math.huge or math.huge end
        local mant = (bytes[7]%%16)/16
        for i = 6, 1, -1 do
            mant = (mant + bytes[i]) / 256
        end
        local v = (1 + mant) * (2^(exp-1023))
        return sign == 1 and -v or v
    end
    local function rproto()
        local p = {}
        p.numparams = ru8()
        p.is_vararg = ru8() == 1
        p.maxstack  = ru8()
        local nc = ru32()
        p.code = {}
        for i = 1, nc do
            local op = _opmap[ru8()]
            local a  = ru8()
            local bx = ru16()
            local b  = math.floor(bx/256)
            local c  = bx%%256
            p.code[i] = {op=op, a=a, b=b, c=c}
        end
        local nk = ru32()
        p.consts = {}
        for i = 1, nk do
            local t = ru8()
            if t == 0 then p.consts[i] = nil
            elseif t == 1 then p.consts[i] = ru8()==1
            elseif t == 2 then p.consts[i] = rdouble()
            elseif t == 3 then p.consts[i] = rstr()
            end
        end
        local nuv = ru32()
        p.upvals = {}
        for i = 1, nuv do
            p.upvals[i] = {instack=ru8()==1, idx=ru8()}
        end
        local np = ru32()
        p.protos = {}
        for i = 1, np do p.protos[i] = rproto() end
        return p
    end
    return rproto()
end

local _root = _reader(_bc)

-- OP constants (must match compiler)
local _LOADK=0 local _LOADNIL=1 local _LOADBOOL=2 local _MOVE=3
local _GETUPVAL=4 local _SETUPVAL=5 local _GETTABUP=6 local _SETTABUP=7
local _GETTABLE=8 local _SETTABLE=9 local _NEWTABLE=10 local _SETLIST=11
local _ADD=12 local _SUB=13 local _MUL=14 local _DIV=15
local _MOD=16 local _POW=17 local _UNM=18 local _NOT=19
local _LEN=20 local _CONCAT=21 local _JMP=22 local _EQ=23
local _LT=24 local _LE=25 local _TEST=26 local _TESTSET=27
local _CALL=28 local _TAILCALL=29 local _RETURN=30 local _FORLOOP=31
local _FORPREP=32 local _TFORLOOP=33 local _CLOSURE=34 local _VARARG=35
local _SELF=36
local _RK_BIAS = 256
local _FPF = 50

local function _rk(regs, consts, x)
    if x >= _RK_BIAS then return consts[x - _RK_BIAS + 1]
    else return regs[x] end
end

-- Execute a proto with given upvalues and varargs
local function _exec(proto, upvals, ...)
    local regs    = {}
    local consts  = proto.consts
    local code    = proto.code
    local protos  = proto.protos
    local pc      = 1
    local varargs = {...}
    local maxpc   = #code

    while pc <= maxpc do
        local ins = code[pc]
        local op, a, b, c = ins.op, ins.a, ins.b, ins.c
        pc = pc + 1

        if op == _LOADK then
            regs[a] = consts[b + 1]

        elseif op == _LOADNIL then
            for i = a, b do regs[i] = nil end

        elseif op == _LOADBOOL then
            regs[a] = b ~= 0
            if c ~= 0 then pc = pc + 1 end

        elseif op == _MOVE then
            regs[a] = regs[b]

        elseif op == _GETUPVAL then
            regs[a] = upvals[b+1] and upvals[b+1].val

        elseif op == _SETUPVAL then
            if upvals[b+1] then upvals[b+1].val = regs[a] end

        elseif op == _GETTABUP then
            local tbl = upvals[b+1] and upvals[b+1].val
            regs[a] = tbl and tbl[_rk(regs, consts, c)]

        elseif op == _SETTABUP then
            local tbl = upvals[a+1] and upvals[a+1].val
            if tbl then tbl[_rk(regs, consts, b)] = _rk(regs, consts, c) end

        elseif op == _GETTABLE then
            regs[a] = regs[b][_rk(regs, consts, c)]

        elseif op == _SETTABLE then
            regs[a][_rk(regs, consts, b)] = _rk(regs, consts, c)

        elseif op == _NEWTABLE then
            regs[a] = {}

        elseif op == _SETLIST then
            local tbl = regs[a]
            local base = (c-1) * _FPF
            for i = 1, b do tbl[base+i] = regs[a+i] end

        elseif op == _ADD  then regs[a] = _rk(regs,consts,b) + _rk(regs,consts,c)
        elseif op == _SUB  then regs[a] = _rk(regs,consts,b) - _rk(regs,consts,c)
        elseif op == _MUL  then regs[a] = _rk(regs,consts,b) * _rk(regs,consts,c)
        elseif op == _DIV  then regs[a] = _rk(regs,consts,b) / _rk(regs,consts,c)
        elseif op == _MOD  then regs[a] = _rk(regs,consts,b) %% _rk(regs,consts,c)
        elseif op == _POW  then regs[a] = _rk(regs,consts,b) ^ _rk(regs,consts,c)
        elseif op == _UNM  then regs[a] = -regs[b]
        elseif op == _NOT  then regs[a] = not regs[b]
        elseif op == _LEN  then regs[a] = #regs[b]

        elseif op == _CONCAT then
            local t = {}
            for i = b, c do t[#t+1] = tostring(regs[i]) end
            regs[a] = table.concat(t)

        elseif op == _JMP then
            -- sBx: bias by 131071 (2^17-1)
            local sbx = b * 256 + c - 131071
            pc = pc + sbx

        elseif op == _EQ then
            local eq = (_rk(regs,consts,b) == _rk(regs,consts,c))
            if eq ~= (a ~= 0) then pc = pc + 1 end

        elseif op == _LT then
            local lt = (_rk(regs,consts,b) < _rk(regs,consts,c))
            if lt ~= (a ~= 0) then pc = pc + 1 end

        elseif op == _LE then
            local le = (_rk(regs,consts,b) <= _rk(regs,consts,c))
            if le ~= (a ~= 0) then pc = pc + 1 end

        elseif op == _TEST then
            if (not not regs[a]) ~= (c ~= 0) then pc = pc + 1 end

        elseif op == _TESTSET then
            if (not not regs[b]) ~= (c ~= 0) then
                pc = pc + 1
            else
                regs[a] = regs[b]
            end

        elseif op == _CALL then
            local fn = regs[a]
            local args = {}
            if b == 0 then
                -- args: R(a+1) to top
                local i = a + 1
                while regs[i] ~= nil do args[#args+1] = regs[i]; i=i+1 end
            else
                for i = 1, b-1 do args[i] = regs[a+i] end
            end
            local results = {fn(table.unpack(args))}
            if c == 0 then
                for i, v in ipairs(results) do regs[a+i-1] = v end
            else
                for i = 0, c-2 do regs[a+i] = results[i+1] end
            end

        elseif op == _TAILCALL then
            local fn = regs[a]
            local args = {}
            for i = 1, b-1 do args[i] = regs[a+i] end
            return fn(table.unpack(args))

        elseif op == _RETURN then
            if b == 1 then return end
            if b == 0 then
                local results = {}
                for i = a, a + 254 do
                    if regs[i] == nil then break end
                    results[#results+1] = regs[i]
                end
                return table.unpack(results)
            end
            local results = {}
            for i = 0, b-2 do results[i+1] = regs[a+i] end
            return table.unpack(results)

        elseif op == _FORPREP then
            local sbx = b * 256 + c - 131071
            regs[a] = regs[a] - regs[a+2]
            pc = pc + sbx

        elseif op == _FORLOOP then
            local sbx = b * 256 + c - 131071
            regs[a] = regs[a] + regs[a+2]
            if regs[a] <= regs[a+1] then
                pc = pc + sbx
                regs[a+3] = regs[a]
            end

        elseif op == _TFORLOOP then
            local fn = regs[a]
            local state = regs[a+1]
            local ctrl  = regs[a+2]
            local results = {fn(state, ctrl)}
            if results[1] ~= nil then
                regs[a+2] = results[1]
                for i = 0, c-1 do regs[a+3+i] = results[i+1] end
            else
                pc = pc + 1
            end

        elseif op == _CLOSURE then
            local child = protos[b+1]
            local cuvs = {}
            for i, uv in ipairs(child.upvals) do
                if uv.instack then
                    -- capture from current registers via a cell
                    cuvs[i] = {val = regs[uv.idx]}
                else
                    cuvs[i] = upvals[uv.idx+1]
                end
            end
            local childProto = child
            regs[a] = function(...)
                return _exec(childProto, cuvs, ...)
            end

        elseif op == _VARARG then
            if b == 0 then
                for i, v in ipairs(varargs) do regs[a+i-1] = v end
            else
                for i = 0, b-2 do regs[a+i] = varargs[i+1] end
            end

        elseif op == _SELF then
            local obj = regs[b]
            regs[a+1] = obj
            regs[a]   = obj[_rk(regs, consts, c)]
        end
    end
end

-- Bootstrap: _ENV upvalue
local _env_uv = {{val = _ENV or getfenv()}}
local _main = function(...) return _exec(_root, _env_uv, ...) end
_main()
]], bytecodeB64, mapLiteral)
end

-- ─── base64 encoder ──────────────────────────────────────────────────────────
local B64CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function toBase64(s)
    local out = {}
    local pad = (3 - #s % 3) % 3
    s = s .. string.rep("\0", pad)
    for i = 1, #s, 3 do
        local b0, b1, b2 = s:byte(i, i+2)
        local v = b0 * 65536 + b1 * 256 + b2
        out[#out+1] = B64CHARS:sub(math.floor(v/262144)%64+1, math.floor(v/262144)%64+1)
        out[#out+1] = B64CHARS:sub(math.floor(v/4096)%64+1,   math.floor(v/4096)%64+1)
        out[#out+1] = B64CHARS:sub(math.floor(v/64)%64+1,     math.floor(v/64)%64+1)
        out[#out+1] = B64CHARS:sub(v%64+1, v%64+1)
    end
    for i = 1, pad do out[#out - pad + i] = "=" end
    return table.concat(out)
end

-- ─── AST → Proto compiler ─────────────────────────────────────────────────────
-- This section compiles the Prometheus AST to Proto objects.
-- It handles the most common Lua 5.1 constructs.

function BytecodeCompiler:compileBlock(block, proto)
    local savedLocals = {}
    local count = 0
    for name, reg in pairs(proto.locals) do
        savedLocals[name] = reg
    end
    for _, stmt in ipairs(block.statements) do
        self:compileStmt(stmt, proto)
    end
    -- Restore register pointer (crude scope end)
end

function BytecodeCompiler:compileStmt(node, proto)
    local k = node.kind

    if k == AstKind.LocalVariableDeclaration then
        local values = node.values or {}
        local vars   = node.variables or {}
        -- Evaluate RHS into fresh registers
        local baseReg = proto.nextReg
        for i, expr in ipairs(values) do
            local r = proto:allocReg()
            self:compileExprInto(expr, proto, r)
        end
        -- Fill missing slots with nil
        for i = #values + 1, #vars do
            local r = proto:allocReg()
            proto:emit(OP.LOADNIL, r, r, 0)
        end
        -- Assign register names
        for i, var in ipairs(vars) do
            local varName = var.name or tostring(var)
            proto.locals[varName] = baseReg + i - 1
        end

    elseif k == AstKind.AssignmentStatement then
        local targets = node.targets or {}
        local values  = node.values  or {}
        -- Evaluate all RHS first into temp regs
        local temps = {}
        for i, expr in ipairs(values) do
            local r = proto:allocReg()
            self:compileExprInto(expr, proto, r)
            temps[i] = r
        end
        -- Assign
        for i, target in ipairs(targets) do
            local src = temps[i] or (function()
                local r = proto:allocReg()
                proto:emit(OP.LOADNIL, r, r, 0)
                return r
            end)()
            self:compileAssignTarget(target, src, proto)
        end
        -- Free temp regs
        proto.nextReg = (temps[1] or proto.nextReg)

    elseif k == AstKind.ReturnStatement then
        local exprs = node.args or {}
        if #exprs == 0 then
            proto:emit(OP.RETURN, 0, 1, 0)
        else
            local base = proto.nextReg
            for i, expr in ipairs(exprs) do
                local r = proto:allocReg()
                self:compileExprInto(expr, proto, r)
            end
            proto:emit(OP.RETURN, base, #exprs + 1, 0)
        end

    elseif k == AstKind.DoStatement then
        self:compileBlock(node.body, proto)

    elseif k == AstKind.WhileStatement then
        local loopStart = proto:pc()
        local condReg = proto:allocReg()
        self:compileExprInto(node.condition, proto, condReg)
        local testPc = proto:emit(OP.TEST, condReg, 0, 0)
        local jmpPc  = proto:emit(OP.JMP, 0, 0, 0)  -- jump over body if false
        self:compileBlock(node.body, proto)
        -- Jump back to loopStart
        local backOfs = loopStart - proto:pc() - 1 + 131071
        proto:emit(OP.JMP, 0, math.floor(backOfs/256), backOfs%256)
        -- Patch exit jump
        local exitOfs = proto:pc() - testPc - 1 + 131071
        proto:patch(jmpPc, "b", math.floor(exitOfs/256))
        proto:patch(jmpPc, "c", exitOfs%256)
        proto:freeReg()

    elseif k == AstKind.RepeatStatement then
        local loopStart = proto:pc()
        self:compileBlock(node.body, proto)
        local condReg = proto:allocReg()
        self:compileExprInto(node.condition, proto, condReg)
        -- if NOT condition, jump back
        proto:emit(OP.TEST, condReg, 0, 0)  -- skip next if condReg is truthy
        local backOfs = loopStart - proto:pc() - 1 + 131071
        proto:emit(OP.JMP, 0, math.floor(backOfs/256), backOfs%256)
        proto:freeReg()

    elseif k == AstKind.IfStatement then
        local exitJmps = {}
        local function compileClause(cond, body)
            local condReg = proto:allocReg()
            self:compileExprInto(cond, proto, condReg)
            proto:emit(OP.TEST, condReg, 0, 0)
            local jmpPc = proto:emit(OP.JMP, 0, 0, 0)
            proto:freeReg()
            self:compileBlock(body, proto)
            -- Jump to exit
            local exitJmpPc = proto:emit(OP.JMP, 0, 0, 0)
            table.insert(exitJmps, exitJmpPc)
            -- Patch the conditional jump to here
            local skipOfs = proto:pc() - jmpPc - 1 + 131071
            proto:patch(jmpPc, "b", math.floor(skipOfs/256))
            proto:patch(jmpPc, "c", skipOfs%256)
        end
        compileClause(node.condition, node.body)
        for _, elseif_ in ipairs(node.elseifs or {}) do
            compileClause(elseif_.condition, elseif_.body)
        end
        if node.elseBody then
            self:compileBlock(node.elseBody, proto)
        end
        -- Patch all exit jumps to current PC
        for _, jpc in ipairs(exitJmps) do
            local ofs = proto:pc() - jpc - 1 + 131071
            proto:patch(jpc, "b", math.floor(ofs/256))
            proto:patch(jpc, "c", ofs%256)
        end

    elseif k == AstKind.NumericFor then
        local startReg = proto:allocReg()
        local limitReg = proto:allocReg()
        local stepReg  = proto:allocReg()
        local loopVar  = proto:allocReg()
        self:compileExprInto(node.start,  proto, startReg)
        self:compileExprInto(node.limit,  proto, limitReg)
        if node.step then
            self:compileExprInto(node.step, proto, stepReg)
        else
            proto:emit(OP.LOADK, stepReg, proto:addConst(1), 0)
        end
        local prepPc = proto:emit(OP.FORPREP, startReg, 0, 0)
        -- loop variable name
        local varName = node.variable and (node.variable.name or tostring(node.variable)) or "_i"
        proto.locals[varName] = loopVar
        self:compileBlock(node.body, proto)
        local loopPc = proto:pc()
        proto:emit(OP.FORLOOP, startReg, 0, 0)
        -- Patch FORPREP: jump to FORLOOP
        local prepOfs = loopPc - prepPc - 1 + 131071
        proto:patch(prepPc, "b", math.floor(prepOfs/256))
        proto:patch(prepPc, "c", prepOfs%256)
        -- Patch FORLOOP: jump back to body start (prepPc+1)
        local bodyStart = prepPc + 1
        local loopOfs = bodyStart - loopPc - 1 + 131071
        proto:patch(loopPc, "b", math.floor(loopOfs/256))
        proto:patch(loopPc, "c", loopOfs%256)
        proto.locals[varName] = nil
        proto.nextReg = startReg

    elseif k == AstKind.GenericFor then
        -- iterFunc, state, ctrl
        local iterReg  = proto:allocReg()
        local stateReg = proto:allocReg()
        local ctrlReg  = proto:allocReg()
        local iters = node.iterators or {}
        if iters[1] then self:compileExprInto(iters[1], proto, iterReg)  end
        if iters[2] then self:compileExprInto(iters[2], proto, stateReg) end
        if iters[3] then self:compileExprInto(iters[3], proto, ctrlReg)  end
        -- TFORLOOP will fill R(iterReg+3) onward
        local loopPc = proto:pc()
        local varCount = #(node.variables or {})
        local tforPc = proto:emit(OP.TFORLOOP, iterReg, 0, varCount)
        -- Bind variable names
        for i, var in ipairs(node.variables or {}) do
            local varName = var.name or tostring(var)
            proto.locals[varName] = iterReg + 2 + i
        end
        self:compileBlock(node.body, proto)
        -- Jump back to TFORLOOP
        local backOfs = loopPc - proto:pc() - 1 + 131071
        proto:emit(OP.JMP, 0, math.floor(backOfs/256), backOfs%256)
        -- Unbind vars
        for _, var in ipairs(node.variables or {}) do
            proto.locals[var.name or tostring(var)] = nil
        end
        proto.nextReg = iterReg

    elseif k == AstKind.FunctionCallStatement then
        local r = proto:allocReg()
        self:compileExprInto(node.expression, proto, r)
        proto:freeReg()

    elseif k == AstKind.FunctionDeclaration or k == AstKind.LocalFunctionDeclaration then
        local funcReg = proto:allocReg()
        self:compileFuncInto(node, proto, funcReg)
        local name = node.name or (node.id and tostring(node.id))
        if name and k == AstKind.LocalFunctionDeclaration then
            proto.locals[name] = funcReg
        elseif name then
            proto:emit(OP.SETTABUP, 0, proto:rk(name), funcReg)
        end

    elseif k == AstKind.BreakStatement then
        -- Simplified: emit a JMP with 0 offset (caller must patch)
        proto:emit(OP.JMP, 0, 0, 0)
    end
end

function BytecodeCompiler:compileExprInto(node, proto, reg)
    if not node then
        proto:emit(OP.LOADNIL, reg, reg, 0)
        return
    end
    local k = node.kind

    if k == AstKind.NumberExpression then
        proto:emit(OP.LOADK, reg, proto:addConst(node.value), 0)

    elseif k == AstKind.StringExpression then
        proto:emit(OP.LOADK, reg, proto:addConst(node.value), 0)

    elseif k == AstKind.BooleanExpression or k == AstKind.TrueExpression then
        proto:emit(OP.LOADBOOL, reg, 1, 0)

    elseif k == AstKind.FalseExpression then
        proto:emit(OP.LOADBOOL, reg, 0, 0)

    elseif k == AstKind.NilExpression then
        proto:emit(OP.LOADNIL, reg, reg, 0)

    elseif k == AstKind.VarargExpression then
        proto:emit(OP.VARARG, reg, 2, 0)

    elseif k == AstKind.VariableExpression then
        local name = node.scope and node.scope:getVariableName(node.id) or tostring(node.id)
        local lreg = proto:resolveLocal(name)
        if lreg then
            if lreg ~= reg then proto:emit(OP.MOVE, reg, lreg, 0) end
        else
            -- Global: GETTABUP 0 (env) K(name)
            proto:emit(OP.GETTABUP, reg, 0, proto:rk(name))
        end

    elseif k == AstKind.IndexExpression then
        local tReg = proto:allocReg()
        self:compileExprInto(node.base, proto, tReg)
        local idx = node.index
        if idx.kind == AstKind.StringExpression then
            proto:emit(OP.GETTABLE, reg, tReg, proto:rk(idx.value))
        elseif idx.kind == AstKind.NumberExpression then
            proto:emit(OP.GETTABLE, reg, tReg, proto:rk(idx.value))
        else
            local iReg = proto:allocReg()
            self:compileExprInto(idx, proto, iReg)
            proto:emit(OP.GETTABLE, reg, tReg, iReg)
            proto:freeReg()
        end
        proto:freeReg()

    elseif k == AstKind.FunctionCallExpression then
        -- Compile function and args into consecutive registers
        local fnReg = proto:allocReg()
        self:compileExprInto(node.base, proto, fnReg)
        local args = node.args or {}
        for _, arg in ipairs(args) do
            local ar = proto:allocReg()
            self:compileExprInto(arg, proto, ar)
        end
        proto:emit(OP.CALL, fnReg, #args + 1, 2)  -- 1 return value into fnReg
        if fnReg ~= reg then proto:emit(OP.MOVE, reg, fnReg, 0) end
        proto.nextReg = fnReg + 1

    elseif k == AstKind.MethodCallExpression then
        local objReg = proto:allocReg()
        self:compileExprInto(node.base, proto, objReg)
        local methodReg = proto:allocReg()  -- R(objReg+1) = obj, R(objReg) = method
        proto:emit(OP.SELF, objReg, objReg, proto:rk(node.method or ""))
        local args = node.args or {}
        for _, arg in ipairs(args) do
            local ar = proto:allocReg()
            self:compileExprInto(arg, proto, ar)
        end
        proto:emit(OP.CALL, objReg, #args + 2, 2)
        if objReg ~= reg then proto:emit(OP.MOVE, reg, objReg, 0) end
        proto.nextReg = objReg + 1

    elseif k == AstKind.AddExpression then
        self:compileBinop(OP.ADD, node, proto, reg)
    elseif k == AstKind.SubExpression then
        self:compileBinop(OP.SUB, node, proto, reg)
    elseif k == AstKind.MulExpression then
        self:compileBinop(OP.MUL, node, proto, reg)
    elseif k == AstKind.DivExpression then
        self:compileBinop(OP.DIV, node, proto, reg)
    elseif k == AstKind.ModExpression then
        self:compileBinop(OP.MOD, node, proto, reg)
    elseif k == AstKind.PowExpression then
        self:compileBinop(OP.POW, node, proto, reg)

    elseif k == AstKind.ConcatExpression then
        local lReg = proto:allocReg()
        local rReg = proto:allocReg()
        self:compileExprInto(node.left,  proto, lReg)
        self:compileExprInto(node.right, proto, rReg)
        proto:emit(OP.CONCAT, reg, lReg, rReg)
        proto:freeReg(2)

    elseif k == AstKind.UnaryMinusExpression then
        local bReg = proto:allocReg()
        self:compileExprInto(node.operand, proto, bReg)
        proto:emit(OP.UNM, reg, bReg, 0)
        proto:freeReg()

    elseif k == AstKind.NotExpression then
        local bReg = proto:allocReg()
        self:compileExprInto(node.operand, proto, bReg)
        proto:emit(OP.NOT, reg, bReg, 0)
        proto:freeReg()

    elseif k == AstKind.LengthExpression then
        local bReg = proto:allocReg()
        self:compileExprInto(node.operand, proto, bReg)
        proto:emit(OP.LEN, reg, bReg, 0)
        proto:freeReg()

    elseif k == AstKind.EqualExpression then
        self:compileCmp(OP.EQ, 1, node, proto, reg)
    elseif k == AstKind.NotEqualExpression then
        self:compileCmp(OP.EQ, 0, node, proto, reg)
    elseif k == AstKind.LessThanExpression then
        self:compileCmp(OP.LT, 1, node, proto, reg)
    elseif k == AstKind.GreaterThanExpression then
        -- a > b  →  b < a
        self:compileCmpSwapped(OP.LT, 1, node, proto, reg)
    elseif k == AstKind.LessOrEqualExpression then
        self:compileCmp(OP.LE, 1, node, proto, reg)
    elseif k == AstKind.GreaterOrEqualExpression then
        self:compileCmpSwapped(OP.LE, 1, node, proto, reg)

    elseif k == AstKind.AndExpression then
        -- R(reg) = left and right
        self:compileExprInto(node.left, proto, reg)
        proto:emit(OP.TESTSET, reg, reg, 0)
        local jmpPc = proto:emit(OP.JMP, 0, 0, 0)
        self:compileExprInto(node.right, proto, reg)
        local ofs = proto:pc() - jmpPc - 1 + 131071
        proto:patch(jmpPc, "b", math.floor(ofs/256))
        proto:patch(jmpPc, "c", ofs%256)

    elseif k == AstKind.OrExpression then
        self:compileExprInto(node.left, proto, reg)
        proto:emit(OP.TESTSET, reg, reg, 1)
        local jmpPc = proto:emit(OP.JMP, 0, 0, 0)
        self:compileExprInto(node.right, proto, reg)
        local ofs = proto:pc() - jmpPc - 1 + 131071
        proto:patch(jmpPc, "b", math.floor(ofs/256))
        proto:patch(jmpPc, "c", ofs%256)

    elseif k == AstKind.FunctionLiteralExpression then
        self:compileFuncInto(node, proto, reg)

    elseif k == AstKind.TableConstructorExpression then
        proto:emit(OP.NEWTABLE, reg, 0, 0)
        local entries = node.entries or {}
        local arrayIdx = 1
        for _, entry in ipairs(entries) do
            if entry.kind == AstKind.TableEntry then
                -- array part
                local vReg = proto:allocReg()
                self:compileExprInto(entry.value, proto, vReg)
                proto:emit(OP.SETLIST, reg, 1, arrayIdx)
                proto:freeReg()
                arrayIdx = arrayIdx + 1
            elseif entry.kind == AstKind.KeyedTableEntry then
                local kReg = proto:allocReg()
                local vReg = proto:allocReg()
                self:compileExprInto(entry.key,   proto, kReg)
                self:compileExprInto(entry.value, proto, vReg)
                proto:emit(OP.SETTABLE, reg, kReg, vReg)
                proto:freeReg(2)
            end
        end
    else
        -- Unknown/unsupported node: load nil
        proto:emit(OP.LOADNIL, reg, reg, 0)
    end
end

function BytecodeCompiler:compileBinop(opcode, node, proto, reg)
    local function rkExpr(expr)
        if expr.kind == AstKind.NumberExpression then
            return proto:rk(expr.value)
        elseif expr.kind == AstKind.StringExpression then
            return proto:rk(expr.value)
        end
        local r = proto:allocReg()
        self:compileExprInto(expr, proto, r)
        return r
    end
    local bv = rkExpr(node.left)
    local cv = rkExpr(node.right)
    proto:emit(opcode, reg, bv, cv)
    -- Free any temp regs we allocated (those >= RK_BIAS are constants, not regs)
    if bv < RK_BIAS and bv >= reg then proto:freeReg() end
    if cv < RK_BIAS and cv >= reg then proto:freeReg() end
end

local RK_BIAS = 256

function BytecodeCompiler:compileCmp(opcode, inv, node, proto, reg)
    local lReg = proto:allocReg()
    local rReg = proto:allocReg()
    self:compileExprInto(node.left,  proto, lReg)
    self:compileExprInto(node.right, proto, rReg)
    proto:emit(opcode, inv == 1 and 0 or 1, lReg, rReg)
    proto:emit(OP.JMP, 0, 0, 1 + 131071)
    proto:emit(OP.LOADBOOL, reg, 0, 1)
    proto:emit(OP.LOADBOOL, reg, 1, 0)
    proto:freeReg(2)
end

function BytecodeCompiler:compileCmpSwapped(opcode, inv, node, proto, reg)
    local lReg = proto:allocReg()
    local rReg = proto:allocReg()
    self:compileExprInto(node.right, proto, lReg)  -- swapped
    self:compileExprInto(node.left,  proto, rReg)
    proto:emit(opcode, inv == 1 and 0 or 1, lReg, rReg)
    proto:emit(OP.JMP, 0, 0, 1 + 131071)
    proto:emit(OP.LOADBOOL, reg, 0, 1)
    proto:emit(OP.LOADBOOL, reg, 1, 0)
    proto:freeReg(2)
end

function BytecodeCompiler:compileFuncInto(node, parentProto, reg)
    local child = Proto:new(parentProto)
    -- Copy parent locals as potential upvalue sources
    for name, r in pairs(parentProto.locals) do
        child.locals[name] = r  -- will resolve as upvalue at use time
    end
    -- Parameters
    local params = node.args or node.params or {}
    child.numparams = 0
    for _, param in ipairs(params) do
        if param.kind == AstKind.VarargExpression then
            child.is_vararg = true
        else
            local name = param.name or tostring(param)
            child:pushLocal(name)
            child.numparams = child.numparams + 1
        end
    end
    child.is_vararg = child.is_vararg or (node.is_vararg == true)
    -- _ENV upvalue slot 0 for the child
    child:addUpval("_ENV", false, 0)

    -- Compile body
    local body = node.body or node
    if body.statements then
        self:compileBlock(body, child)
    end
    -- Ensure we always have a RETURN
    local last = child.code[#child.code]
    if not last or last.op ~= OP.RETURN then
        child:emit(OP.RETURN, 0, 1, 0)
    end

    -- Add child proto to parent
    table.insert(parentProto.protos, child)
    local protoIdx = #parentProto.protos - 1
    parentProto:emit(OP.CLOSURE, reg, protoIdx, 0)
end

function BytecodeCompiler:compileAssignTarget(target, srcReg, proto)
    local k = target.kind
    if k == AstKind.AssignmentVariable or k == AstKind.VariableExpression then
        local name = target.scope and target.scope:getVariableName(target.id) or tostring(target.id)
        local lreg = proto:resolveLocal(name)
        if lreg then
            if lreg ~= srcReg then proto:emit(OP.MOVE, lreg, srcReg, 0) end
        else
            proto:emit(OP.SETTABUP, 0, proto:rk(name), srcReg)
        end
    elseif k == AstKind.IndexExpression then
        local tReg = proto:allocReg()
        self:compileExprInto(target.base, proto, tReg)
        local idx = target.index
        if idx.kind == AstKind.StringExpression then
            proto:emit(OP.SETTABLE, tReg, proto:rk(idx.value), srcReg)
        elseif idx.kind == AstKind.NumberExpression then
            proto:emit(OP.SETTABLE, tReg, proto:rk(idx.value), srcReg)
        else
            local iReg = proto:allocReg()
            self:compileExprInto(idx, proto, iReg)
            proto:emit(OP.SETTABLE, tReg, iReg, srcReg)
            proto:freeReg()
        end
        proto:freeReg()
    end
end

-- ─── top-level compile entry point ───────────────────────────────────────────
function BytecodeCompiler:compile(ast)
    -- Build root proto
    local root = Proto:new(nil)
    root.is_vararg = true
    root.numparams = 0
    -- _ENV is upvalue 0 of root proto (open upvalue from outside)
    root:addUpval("_ENV", false, 0)

    -- Compile top-level block
    self:compileBlock(ast.body, root)

    -- Ensure trailing RETURN
    local last = root.code[#root.code]
    if not last or last.op ~= OP.RETURN then
        root:emit(OP.RETURN, 0, 1, 0)
    end

    -- Serialize proto to binary
    local binary = serializeProto(root, self.opmap)

    -- Base64 encode
    local b64 = toBase64(binary)

    -- Build VM source
    local vmSource = buildVMSource(b64, self.inv_opmap)

    -- Parse VM source back into an AST node and return it
    -- The VM source is a self-contained Lua script — wrap as a do..end block
    -- We return a fake "already compiled" AST by wrapping the raw source
    -- in a StringExpression that the pipeline can emit directly.
    -- The Vmify step will extract this.
    return vmSource
end

return BytecodeCompiler
