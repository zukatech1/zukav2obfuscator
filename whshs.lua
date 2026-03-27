-- presets.lua
-- All presets are executor-safe (no debug-lib traps).
--
-- EXECUTOR SAFETY RULES:
--   EXCLUDED from all presets:
--     * HookDetection   — crashes on hooked debug.getinfo
--     * AntiTamper      — requires debug.sethook / string.dump, both hooked
--     * AntiDump (UseEnvProxy=true) — setfenv proxy breaks executor env injection
--   SAFE:
--     * AntiDump (GCInterval only) — GC pressure, no debug lib
--     * PcallSilencer (Mode="forward") — silences outer executor pcall wrap
--     * CffIntegrity / XorTable / ShadowRegisters / DynamicXOR — pure Lua, always safe
--     * VirtualGlobals — hides globals from scanners
--     * VmifyBC — custom bytecode VM, fully custom ISA, no shared fingerprints
--     * BlobCompress — LZW + XOR on the blob, pure Lua
--
-- STEP ORDERING GUIDE:
--   1.  PcallSilencer          (wrap whole script first if used)
--   2.  CffIntegrity / XorTable (inject traps/rewrites before VM sees the code)
--   3.  EncryptStrings / DynamicXOR / ShadowRegisters (transform the code body)
--   4.  VmifyBC or Vmify       (compile to bytecode — bakes above layers into blob)
--   5.  Second Vmify pass      (double-VM; skip for VmifyBC)
--   6.  ConstantArray          (pull constants into indexed table)
--   7.  NumbersToExpressions   (arithmetic fog on numbers)
--   8.  ConstantsObfuscator    (mock strings / mangle number constants)
--   9.  StatementFlattener     (flatten if/function bodies)
--  10.  OpaquePredicates        (inject always-true/false conditions)
--  11.  JunkStatements          (inject dead code)
--  12.  VirtualGlobals          (hide global references)
--  13.  AntiDump                (GC pressure)
--  14.  FakeLoopWrap            (wrap blocks in dead repeat loops)
--  15.  WrapInFunction          (final closure wrap — always last before compress)
--  16.  BlobCompress            (LZW compress entire output)
--      OR Compressor            (variable-name compressor — mutually exclusive)
--
-- VmifyBC + BlobCompress is a very strong combo: the repetitive VM dispatch
-- table compresses ~55% with LZW, so you get a smaller output than Vmify +
-- Compressor while being harder to reverse-engineer.

return {

	-- ─────────────────────────────────────────────────────────────────────────
	-- MINI  — Bare minimum. Fastest compile, smallest output.
	--         Good for size-sensitive or time-sensitive scripts.
	-- ─────────────────────────────────────────────────────────────────────────
	["Mini"] = {
		LuaVersion = "Lua51"; VarNamePrefix = "_z"; NameGenerator = "SegAddr";
		PrettyPrint = false; Seed = 0;
		Steps = {
			--{ Name = "Vmify";          Settings = {} };
			{ Name = "NumbersToExpressions"; Settings = {} };
                                                            { Name = "StatementFlattener";   Settings = { FlattenIf = true; FlattenFunctions = true; Threshold = 0.75 } };
		};
		Hercules = nil;
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- WEAK  — String hiding only, no VM. Good for HttpGet scripts where
	--         you want minimal overhead but some string protection.
	-- ─────────────────────────────────────────────────────────────────────────
	["Weak"] = {
		LuaVersion = "Lua51"; VarNamePrefix = "_"; NameGenerator = "SegAddr";
		PrettyPrint = false; Seed = 0;
		Steps = {
			{ Name = "EncryptStrings"; Settings = {} };
			{ Name = "DynamicXOR";     Settings = { Treshold = 0.25 } };
			{ Name = "WrapInFunction"; Settings = {} };
		};
		Hercules = nil;
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- DEFAULT  — Balanced everyday obfuscation. VM + string encryption +
	--            constant hiding. Works everywhere, reasonable compile time.
	-- ─────────────────────────────────────────────────────────────────────────
	["Default"] = {
		LuaVersion = "Lua51"; VarNamePrefix = ""; NameGenerator = "Hazard";
		PrettyPrint = false; Seed = 0;
		Steps = {
			{ Name = "Vmify";          Settings = {} };
			{ Name = "EncryptStrings"; Settings = {} };
			{ Name = "DynamicXOR";     Settings = { Treshold = 0.2 } };
			{ Name = "ConstantArray";  Settings = {
				Treshold = 0.75; StringsOnly = false; Shuffle = true; Rotate = true;
				LocalWrapperTreshold = 0.5; LocalWrapperCount = 2; LocalWrapperArgCount = 5;
			}};
			{ Name = "WrapInFunction"; Settings = {} };
		};
		Hercules = nil;
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- MEDIUM  — Number fog + Zalgo variable names on top of Default.
	-- ─────────────────────────────────────────────────────────────────────────
	["Medium"] = {
		LuaVersion = "Lua51"; VarNamePrefix = ""; NameGenerator = "ZukaZalgo";
		PrettyPrint = false; Seed = 0;
		Steps = {
			{ Name = "EncryptStrings";       Settings = {} };
			{ Name = "Vmify";                Settings = {} };
			{ Name = "ConstantArray";        Settings = {
				Treshold = 1; StringsOnly = true; Shuffle = true; Rotate = true;
				LocalWrapperTreshold = 0;
			}};
			{ Name = "NumbersToExpressions"; Settings = {} };
			{ Name = "WrapInFunction";       Settings = {} };
		};
		Hercules = nil;
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- STRONG  — Double-VM pass. Strings encrypted between layers.
	-- ─────────────────────────────────────────────────────────────────────────
	["Strong"] = {
		LuaVersion = "Lua51"; VarNamePrefix = ""; NameGenerator = "SegAddr";
		PrettyPrint = false; Seed = 0;
		Steps = {
			{ Name = "Vmify";                Settings = {} };
			{ Name = "EncryptStrings";       Settings = {} };
			{ Name = "Vmify";                Settings = {} };
			{ Name = "ConstantArray";        Settings = {
				Treshold = 1; StringsOnly = true; Shuffle = true; Rotate = true;
				LocalWrapperTreshold = 0;
			}};
			{ Name = "NumbersToExpressions"; Settings = {} };
			{ Name = "WrapInFunction";       Settings = {} };
		};
		Hercules = nil;
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- EXECUTOR  — Direct executor injection. Silences outer pcall wraps,
	--             hides globals from scanners, double-VM pass.
	-- ─────────────────────────────────────────────────────────────────────────
	["Executor"] = {
		LuaVersion = "Lua51"; VarNamePrefix = ""; NameGenerator = "SegAddr";
		PrettyPrint = true; Seed = 0;
		Steps = {
			{ Name = "Cuteify";              Settings = {
				Threshold       = 1.0;
				Intensity       = 3;
				SplitStrings    = true;
				HomoglyphInject = true;
				DecoyCount      = 3;
				DecoyThreshold  = 0.75;
			}};
			{ Name = "AntiDump";             Settings = { GCInterval = 50 } };
                                                            { Name = "PcallSilencer";        Settings = { Mode = "forward"; MaxDepth = 6 } };
			{ Name = "EncryptStrings";       Settings = {} };
			{ Name = "Vmify";                Settings = {} };
			{ Name = "DynamicXOR";           Settings = { Treshold = 0.7 } };
			{ Name = "ConstantsObfuscator";  Settings = {
				ObfuscateNumbers = true; ObfuscateStrings = true;
				MockStringChance = 6; MinAbsValue = 3;
			}};
			{ Name = "Vmify";                Settings = {} };
			{ Name = "ShadowRegisters";      Settings = { Density = 0.25; ShadowSize = 16 } };
			{ Name = "ConstantArray";        Settings = {
				Treshold = 1; StringsOnly = false; Shuffle = true; Rotate = true;
				LocalWrapperTreshold = 0.5; LocalWrapperCount = 2; LocalWrapperArgCount = 8;
			}};
			{ Name = "NumbersToExpressions"; Settings = { Treshold = 0.8; InternalTreshold = 0.2 } };
			{ Name = "VirtualGlobals";       Settings = { Treshold = 1; UseNumericKeys = true } };
			{ Name = "OpaquePredicates";     Settings = { Treshold = 0.9; InjectionsPerBlock = 1 } };
			{ Name = "JunkStatements";       Settings = {
				InjectionCount = 1; Treshold = 0.5; TableWriteRatio = 0.4;
				ChainLength = 3; TableWriteCount = 2;
			}};
			{ Name = "FakeLoopWrap";         Settings = { Treshold = 0.35 } };
			{ Name = "WrapInFunction";       Settings = {} };
			{ Name = "Compressor";           Settings = { MinLength = 10 } };
                                                            { Name = "ZukaZalgo", Settings = { Density = 0.85, MaxMarks = 8 } };
		};
		Hercules = nil;
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- KAWAII  — Ironically cute, unironically hard to reverse.
	--           Cuteify runs BEFORE EncryptStrings so the uwu'd + split +
	--           homoglyph-poisoned strings get baked INTO the encryption layer.
	--           Decoy strings flood the constant pool with kawaii noise.
	--           Kawaii name generator on top for maximum visual chaos.
	--           Executor-safe: no debug-lib traps.
	-- ─────────────────────────────────────────────────────────────────────────
	["Kawaii"] = {
		LuaVersion = "Lua51"; VarNamePrefix = ""; NameGenerator = "kawaii";
		PrettyPrint = false; Seed = 0;
		Steps = {
			{ Name = "Cuteify";              Settings = {
				Threshold       = 1.0;
				Intensity       = 3;
				SplitStrings    = true;
				HomoglyphInject = true;
				DecoyCount      = 3;
				DecoyThreshold  = 0.75;
			}};
			{ Name = "Vmify";                Settings = {} };
			{ Name = "EncryptStrings";       Settings = {} };
			{ Name = "DynamicXOR";           Settings = { Treshold = 0.6 } };
			{ Name = "ConstantsObfuscator";  Settings = {
				ObfuscateNumbers = true; ObfuscateStrings = true;
				MockStringChance = 6;   MinAbsValue = 3;
			}};
			{ Name = "Vmify";                Settings = {} };
			{ Name = "ShadowRegisters";      Settings = { Density = 0.25; ShadowSize = 16 } };
			{ Name = "ConstantArray";        Settings = {
				Treshold = 1; StringsOnly = false; Shuffle = true; Rotate = true;
				LocalWrapperTreshold = 0.5; LocalWrapperCount = 2; LocalWrapperArgCount = 8;
			}};
			{ Name = "NumbersToExpressions"; Settings = { Treshold = 0.8; InternalTreshold = 0.2 } };
			{ Name = "OpaquePredicates";     Settings = { Treshold = 0.85; InjectionsPerBlock = 1 } };
			{ Name = "JunkStatements";       Settings = {
				InjectionCount = 2; Treshold = 0.6; TableWriteRatio = 0.4;
				ChainLength = 3;    TableWriteCount = 2;
			}};
			{ Name = "VirtualGlobals";       Settings = { Treshold = 1; UseNumericKeys = true } };
			{ Name = "FakeLoopWrap";         Settings = { Treshold = 0.35 } };
			{ Name = "WrapInFunction";       Settings = {} };
			{ Name = "Compressor";           Settings = { MinLength = 10 } };
		};
		Hercules = nil;
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- VMIFYBC  — Custom bytecode VM. VmifyBC compiles your script to a binary
	--            blob with a fully custom ISA — zero shared fingerprints with
	--            IronBrew2, Luraph, or any public obfuscator. BlobCompress
	--            runs last; the repetitive VM dispatch table LZW-compresses
	--            ~55%, so output is often smaller than Vmify + Compressor.
	-- ─────────────────────────────────────────────────────────────────────────
	["VmifyBC"] = {
		LuaVersion = "Lua51"; VarNamePrefix = ""; NameGenerator = "SegAddr";
		PrettyPrint = false; Seed = 0;
		Steps = {
			{ Name = "VmifyBC";        Settings = { XorKey = 0; ShuffleOpcodes = true } };
			{ Name = "EncryptStrings"; Settings = {} };
			{ Name = "ConstantArray";  Settings = {
				Treshold = 1; StringsOnly = false; Shuffle = true; Rotate = true;
				LocalWrapperTreshold = 0.5; LocalWrapperCount = 2; LocalWrapperArgCount = 6;
			}};
			{ Name = "WrapInFunction"; Settings = {} };
			{ Name = "BlobCompress";   Settings = {} };
		};
		Hercules = nil;
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- VMIFYBC_STRONG  — VmifyBC with full executor-safe noise stack.
	--                   XorTable rewrites bit32 before the bytecode pass
	--                   so it never appears in the VM source.
	--                   ShadowRegisters + DynamicXOR baked into the blob.
	--                   BlobCompress at the end.
	-- ─────────────────────────────────────────────────────────────────────────
	["VmifyBC_Strong"] = {
		LuaVersion = "Lua51"; VarNamePrefix = ""; NameGenerator = "Hex";
		PrettyPrint = false; Seed = 0;
		Steps = {
			{ Name = "PcallSilencer";        Settings = { Mode = "forward"; MaxDepth = 6 } };
			{ Name = "XorTable";             Settings = { ShuffleTable = true; ReplaceBit32 = true } };
			{ Name = "EncryptStrings";       Settings = {} };
			{ Name = "DynamicXOR";           Settings = { Treshold = 0.3 } };
			{ Name = "ShadowRegisters";      Settings = { Density = 0.25; ShadowSize = 16 } };
			{ Name = "VmifyBC";              Settings = { XorKey = 0; ShuffleOpcodes = true } };
			{ Name = "ConstantArray";        Settings = {
				Treshold = 1; StringsOnly = false; Shuffle = true; Rotate = true;
				LocalWrapperTreshold = 0.5; LocalWrapperCount = 2; LocalWrapperArgCount = 8;
			}};
			{ Name = "NumbersToExpressions"; Settings = { Treshold = 0.8; InternalTreshold = 0.2 } };
			{ Name = "VirtualGlobals";       Settings = { Treshold = 1; UseNumericKeys = true } };
			{ Name = "OpaquePredicates";     Settings = { Treshold = 0.6; InjectionsPerBlock = 1 } };
			{ Name = "JunkStatements";       Settings = {
				InjectionCount = 1; Treshold = 0.7; TableWriteRatio = 0.4;
				ChainLength = 3; TableWriteCount = 2;
			}};
			{ Name = "WrapInFunction";       Settings = {} };
			{ Name = "BlobCompress";         Settings = {} };
		};
		Hercules = nil;
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- TIER1  — High-effort. XOR lookup table, shadow registers, double-VM,
	--          full constant coverage, opaque predicates, junk code, GC pressure.
	--          No debug-lib traps. Runs in all executors.
	-- ─────────────────────────────────────────────────────────────────────────
	["Tier1"] = {
		LuaVersion = "Lua51"; VarNamePrefix = ""; NameGenerator = "Unicode";
		PrettyPrint = false; Seed = 20;
		Steps = {
			{ Name = "PcallSilencer";        Settings = { Mode = "forward"; MaxDepth = 5 } };
			{ Name = "Vmify";                Settings = {} };
			{ Name = "DynamicXOR";           Settings = { Treshold = 0.2 } };
			{ Name = "EncryptStrings";       Settings = {} };
			{ Name = "ShadowRegisters";      Settings = { Density = 0.3; ShadowSize = 20 } };
			{ Name = "Vmify";                Settings = {} };
			{ Name = "ConstantArray";        Settings = {
				Treshold = 1; StringsOnly = true; Shuffle = true; Rotate = true;
				LocalWrapperTreshold = 1; LocalWrapperCount = 3; LocalWrapperArgCount = 12;
			}};
			{ Name = "NumbersToExpressions"; Settings = { Treshold = 1; InternalTreshold = 0.3 } };
			{ Name = "OpaquePredicates";     Settings = { Treshold = 0.85; InjectionsPerBlock = 2 } };
			{ Name = "JunkStatements";       Settings = {
				InjectionCount = 2; Treshold = 0.9; TableWriteRatio = 0.5;
				ChainLength = 4; TableWriteCount = 3;
			}};
			{ Name = "AntiDump";             Settings = { GCInterval = 50 } };
			{ Name = "FakeLoopWrap";         Settings = { Treshold = 0.35 } };
			{ Name = "WrapInFunction";       Settings = {} };
			{ Name = "Compressor";           Settings = { MinLength = 10 } };
		};
		Hercules = nil;
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- TIER1_BC  — Tier1 strength using VmifyBC instead of double-Vmify.
	--             CffIntegrity pure-arithmetic trap, XorTable + ShadowRegisters
	--             + EncryptStrings all compiled into the bytecode blob.
	--             BlobCompress instead of Compressor at the end.
	-- ─────────────────────────────────────────────────────────────────────────
	["Tier1_BC"] = {
		LuaVersion = "Lua51"; VarNamePrefix = ""; NameGenerator = "lI";
		PrettyPrint = false; Seed = 0;
		Steps = {
			{ Name = "PcallSilencer";        Settings = { Mode = "forward"; MaxDepth = 5 } };
			{ Name = "CffIntegrity";         Settings = { TableSize = 7; TrapIndex = 0 } };
			{ Name = "XorTable";             Settings = { ShuffleTable = true; ReplaceBit32 = true } };
			{ Name = "EncryptStrings";       Settings = {} };
			{ Name = "DynamicXOR";           Settings = { Treshold = 0.25 } };
			{ Name = "ShadowRegisters";      Settings = { Density = 0.3; ShadowSize = 20 } };
			{ Name = "VmifyBC";              Settings = { XorKey = 0; ShuffleOpcodes = true } };
			{ Name = "ConstantArray";        Settings = {
				Treshold = 1; StringsOnly = false; Shuffle = true; Rotate = true;
				LocalWrapperTreshold = 1; LocalWrapperCount = 3; LocalWrapperArgCount = 12;
			}};
			{ Name = "NumbersToExpressions"; Settings = { Treshold = 1; InternalTreshold = 0.3 } };
			{ Name = "OpaquePredicates";     Settings = { Treshold = 0.85; InjectionsPerBlock = 2 } };
			{ Name = "JunkStatements";       Settings = {
				InjectionCount = 2; Treshold = 0.9; TableWriteRatio = 0.5;
				ChainLength = 4; TableWriteCount = 3;
			}};
			{ Name = "VirtualGlobals";       Settings = { Treshold = 1; UseNumericKeys = true } };
			{ Name = "AntiDump";             Settings = { GCInterval = 50 } };
			{ Name = "FakeLoopWrap";         Settings = { Treshold = 0.35 } };
			{ Name = "WrapInFunction";       Settings = {} };
			{ Name = "BlobCompress";         Settings = {} };
		};
		Hercules = nil;
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- NOVMMAX  — Maximum obfuscation WITHOUT any VM step.
	--            For environments with strict bytecode limits. Full Hercules.
	-- ─────────────────────────────────────────────────────────────────────────
	["NoVmMax"] = {
		LuaVersion = "Lua51"; VarNamePrefix = ""; NameGenerator = "MangledShuffled";
		PrettyPrint = false; Seed = 0;
		Steps = {
			{ Name = "PcallSilencer";        Settings = { Mode = "forward"; MaxDepth = 5 } };
			{ Name = "EncryptStrings";       Settings = {} };
			{ Name = "XorTable";             Settings = { ShuffleTable = true; ReplaceBit32 = true } };
			{ Name = "ConstantsObfuscator";  Settings = {
				ObfuscateNumbers = true; ObfuscateStrings = true;
				MockStringChance = 6; MinAbsValue = 3;
			}};
			{ Name = "ShadowRegisters";      Settings = { Density = 0.35; ShadowSize = 24 } };
			{ Name = "StatementFlattener";   Settings = { FlattenIf = true; FlattenFunctions = true; Threshold = 0.75 } };
			{ Name = "ConstantArray";        Settings = {
				Treshold = 1; StringsOnly = false; Shuffle = true; Rotate = true;
				LocalWrapperTreshold = 0;
			}};
			{ Name = "NumbersToExpressions"; Settings = { Treshold = 1; InternalTreshold = 0.3 } };
			{ Name = "JunkStatements";       Settings = {
				InjectionCount = 5; Treshold = 0.8; TableWriteRatio = 0.5;
				ChainLength = 3; TableWriteCount = 3;
			}};
			{ Name = "DynamicXOR";           Settings = { Treshold = 0.25 } };
			{ Name = "FakeLoopWrap";         Settings = { Treshold = 0.35 } };
			{ Name = "WrapInFunction";       Settings = {} };
		};
		Hercules = { control_flow = true; garbage_code = true; opaque_predicates = true; variable_renaming = true; string_encoding = true; intensity = "max" };
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- ZURAPHMAX  — Everything turned up with double-Vmify. CFF integrity trap,
	--              XOR table, shadow registers, virtual globals, full Hercules.
	--              Executor-safe: zero debug-lib traps. Slowest preset.
	-- ─────────────────────────────────────────────────────────────────────────
	["ZuraphMax"] = {
		LuaVersion = "Lua51"; VarNamePrefix = "_x"; NameGenerator = "SegAddr";
		PrettyPrint = false; Seed = 0;
		Steps = {
			{ Name = "PcallSilencer";        Settings = { Mode = "forward"; MaxDepth = 5 } };
			{ Name = "Vmify";                Settings = {} };
			{ Name = "EncryptStrings";       Settings = {} };
			{ Name = "ConstantsObfuscator";  Settings = {
				ObfuscateNumbers = true; ObfuscateStrings = true;
				MockStringChance = 8; MinAbsValue = 5;
			}};
			{ Name = "ShadowRegisters";      Settings = { Density = 0.4; ShadowSize = 32 } };
			{ Name = "StatementFlattener";   Settings = { FlattenIf = true; FlattenFunctions = true; Threshold = 0.85 } };
			{ Name = "Vmify";                Settings = {} };
			{ Name = "ConstantArray";        Settings = {
				Treshold = 1; StringsOnly = false; Shuffle = true; Rotate = true;
				LocalWrapperTreshold = 1; LocalWrapperCount = 3; LocalWrapperArgCount = 12;
			}};
			{ Name = "NumbersToExpressions"; Settings = { Treshold = 1; InternalTreshold = 0.3 } };
			{ Name = "DynamicXOR";           Settings = { Treshold = 0.8 } };
			{ Name = "OpaquePredicates";     Settings = { Treshold = 0.85; InjectionsPerBlock = 2 } };
			{ Name = "JunkStatements";       Settings = {
				InjectionCount = 1; Treshold = 0.9; TableWriteRatio = 0.5;
				ChainLength = 4; TableWriteCount = 4;
			}};
			{ Name = "AntiDump";             Settings = { GCInterval = 60 } };
			{ Name = "VirtualGlobals";       Settings = { Treshold = 1; UseNumericKeys = true } };
			{ Name = "FakeLoopWrap";         Settings = { Treshold = 0.4 } };
			{ Name = "WrapInFunction";       Settings = {} };
			{ Name = "Compressor";           Settings = { MinLength = 10 } };
		};
		Hercules = nil;
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- ZURAPHMAX_BC  — ZuraphMax with VmifyBC as the engine instead of Vmify.
	--                 XorTable + ShadowRegisters + EncryptStrings all compile
	--                 INTO the bytecode blob, not just the wrapper around it.
	--                 BlobCompress replaces Compressor (~55% size savings).
	--                 Full Hercules post-pass still runs on the final source.
	--                 This is the hardest-to-reverse preset in the suite.
	-- ─────────────────────────────────────────────────────────────────────────
	["ZuraphMax_BC"] = {
		LuaVersion = "Lua51"; VarNamePrefix = ""; NameGenerator = "MangledShuffled";
		PrettyPrint = false; Seed = 0;
		Steps = {
			{ Name = "PcallSilencer";        Settings = { Mode = "forward"; MaxDepth = 5 } };
			{ Name = "CffIntegrity";         Settings = { TableSize = 9; TrapIndex = 0 } };
			{ Name = "XorTable";             Settings = { ShuffleTable = true; ReplaceBit32 = true } };
			{ Name = "EncryptStrings";       Settings = {} };
			{ Name = "DynamicXOR";           Settings = { Treshold = 0.4 } };
			{ Name = "ConstantsObfuscator";  Settings = {
				ObfuscateNumbers = true; ObfuscateStrings = false;
				MockStringChance = 8; MinAbsValue = 5;
			}};
			{ Name = "ShadowRegisters";      Settings = { Density = 0.4; ShadowSize = 32 } };
			{ Name = "StatementFlattener";   Settings = { FlattenIf = true; FlattenFunctions = true; Threshold = 0.85 } };
			{ Name = "VmifyBC";              Settings = { XorKey = 0; ShuffleOpcodes = true } };
			{ Name = "ConstantArray";        Settings = {
				Treshold = 1; StringsOnly = false; Shuffle = true; Rotate = true;
				LocalWrapperTreshold = 1; LocalWrapperCount = 3; LocalWrapperArgCount = 12;
			}};
			{ Name = "NumbersToExpressions"; Settings = { Treshold = 1; InternalTreshold = 0.3 } };
			{ Name = "OpaquePredicates";     Settings = { Treshold = 0.85; InjectionsPerBlock = 2 } };
			{ Name = "JunkStatements";       Settings = {
				InjectionCount = 4; Treshold = 0.9; TableWriteRatio = 0.5;
				ChainLength = 4; TableWriteCount = 4;
			}};
			{ Name = "AntiDump";             Settings = { GCInterval = 60 } };
			{ Name = "VirtualGlobals";       Settings = { Treshold = 1; UseNumericKeys = true } };
			{ Name = "FakeLoopWrap";         Settings = { Treshold = 0.4 } };
			{ Name = "WrapInFunction";       Settings = {} };
			{ Name = "BlobCompress";         Settings = {} };
		};
		Hercules = { control_flow = true; garbage_code = true; opaque_predicates = true; variable_renaming = true; string_encoding = true; intensity = "max" };
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- HTTPGET  — For scripts fetched + loadstring'd via game:HttpGet.
	--            Unicode names make source dumps unreadable in executor consoles.
	-- ─────────────────────────────────────────────────────────────────────────
	["HttpGet"] = {
		LuaVersion = "Lua51"; VarNamePrefix = ""; NameGenerator = "Unicode";
		PrettyPrint = false; Seed = 0;
		Steps = {
			{ Name = "EncryptStrings"; Settings = {} };
			{ Name = "DynamicXOR";     Settings = { Treshold = 1 } };
			{ Name = "Vmify";          Settings = {} };
			{ Name = "ConstantArray";  Settings = {
				Treshold = 1; StringsOnly = false; Shuffle = true; Rotate = true;
				LocalWrapperTreshold = 1; LocalWrapperCount = 3; LocalWrapperArgCount = 8;
			}};
			{ Name = "JunkStatements"; Settings = {
				InjectionCount = 2; Treshold = 0.7; TableWriteRatio = 0.4;
				ChainLength = 2; TableWriteCount = 2;
			}};
			{ Name = "WrapInFunction"; Settings = {} };
		};
		Hercules = { control_flow = true; garbage_code = true; opaque_predicates = false; variable_renaming = false; intensity = "mid" };
	};

	-- ─────────────────────────────────────────────────────────────────────────
	-- DEBUG  — Development preset. VmifyBC with no noise so you can still
	--          trace execution issues. ShuffleOpcodes=false for readability.
	--          Swap for VmifyBC or Tier1_BC when releasing.
	-- ─────────────────────────────────────────────────────────────────────────
	["Debug"] = {
		LuaVersion = "Lua51"; VarNamePrefix = "_z"; NameGenerator = "SegAddr";
		PrettyPrint = false; Seed = 0;
		Steps = {
			{ Name = "VmifyBC";        Settings = { XorKey = 0; ShuffleOpcodes = false } };
			{ Name = "WrapInFunction"; Settings = {} };
		};
		Hercules = nil;
	};

}
