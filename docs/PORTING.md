# Porting an ASI mod to Apple Silicon

How the Axiom Force addresses were found, how to re-derive them after a game
update, and how to judge whether another Windows ASI mod can be ported the same
way.

## The core idea

A Windows ASI plugin contains no addresses that are useful on macOS. Different
architecture, different binary format, different layout. Copying offsets is
hopeless.

What it does contain, if it is careful, are the **values it validates against
before it will bind**. A well written mod does not trust a scanned address
blindly; it reads the location and confirms the value matches what vanilla is
expected to be. Those expected values are architecture independent, because they
come from the game's data rather than from its layout.

That turns an unbounded search into a fingerprint scan.

## Worked example: Axiom Force

### 1. What failed first

The initial approach was to disassemble the Mac binary's RemoteCatch code, list
every global float it reads, and probe them one at a time from a live tuning
file. That produced 54 candidate addresses and no result.

The reason is visible in hindsight. The values at those addresses were `0.1`,
`1.0`, `1.5`, `2.0`, `5.0`, `30.0`, `40.0`, `60.0`, `360.0` — coefficients,
blend weights, speeds, and an angle. A reach distance was not among them,
because the range value is not read by the code that was disassembled.

Worse, the tests were being run at `range = 3000`. The Windows mod's own
documentation notes the game ignores extreme values, so a correct address and an
incorrect one produced identical results. Two failure modes were stacked on top
of each other.

### 2. What the ASI gave up

Disassembling `SuperAxiomForce.asi` with `objdump -d` and looking for float
comparisons produced two adjacent `ucomiss` instructions:

```text
movss   (%rdi), %xmm0
ucomiss 0x2e2ba(%rip), %xmm0    # 0x180033558
jp      <bail>
jne     <bail>
movss   (%rbx), %xmm0
ucomiss 0x2e2af(%rip), %xmm0    # 0x18003355c
jp      <bail>
jne     <bail>
```

Two constants, checked back to back, either of which aborts the bind. Reading
them out of `.rdata`:

```text
180033550  ... 0000a041 00002042   ->  20.0, 40.0
180033560  0000fa43 00007a44       ->  500.0, 1000.0
```

`20.0` and `40.0` are the vanilla range and pull speed. `500.0` and `1000.0` are
just the INI defaults.

The nearby fallback RVAs `0x5E9EB28` and `0x5E9F668` are useless as addresses,
but their **difference** is not: `0xB40`. Two values that far apart in one build
are likely to be similarly spaced in another, because the spacing reflects source
declaration order rather than absolute layout.

### 3. Scanning for the pair

`scan_value_pair` in `src/axiom_force_service.mm` walks every `__DATA` section
of the loaded game image, records every address holding `20.0` and every address
holding `40.0`, and logs the pairs that sit close together.

On the mapped build that produced 180 range hits and 50 pull hits. Far too many
to test individually — but two filters collapse it:

1. **Only one `40.0` is referenced by RemoteCatch code.** That was already known
   from the earlier disassembly work, which turned out to be useful after all,
   just not for the reason intended.
2. **Only one `20.0` sits the Windows distance below it.**

```text
scan: pair range=0x10881926c pull=0x108819dec delta=0xb80
```

`0xb80` against the Windows `0xB40` — a drift of `0x40`, exactly the order of
difference expected between two builds of the same source.

### 4. Confirming

Write to the candidate and read back the old value. The log line

```text
override 0x10881926c 20 -> 95
```

reports a preimage of exactly `20`, matching the constant the ASI demands. That
is the confirmation. A plausible-looking address holding a plausible-looking
value would not read back the exact vanilla constant.

Then test in game at a **modest** value. `95`, not `3000`.

## Re-deriving after a game update

A game update changes `LC_UUID`, the resolver refuses to bind, and the mod goes
quiet. To restore it:

1. Launch the updated game with the dylib injected and play for about a minute.
   The scan runs roughly 45 seconds in on every launch.
2. Read the log for `scan: pair` lines.
3. Keep the pairs whose spacing is near `0xb80`.
4. Confirm the winner by writing to it. The read-back must be exactly `20`.
5. Update `kKnownBuildUuid` and `kKnownRangeUnslid` in
   `src/axiom_force_service.mm`, rebuild, redeploy.

This keeps working as long as the developers leave vanilla range at `20.0` and
pull at `40.0`. The fingerprint is the game's data, not its layout.

## Judging whether another ASI mod will port

Ask what the mod actually writes.

**Good candidates** read and write *data values* — floats and integers in static
memory. These port well. Recover the validation constants, scan, confirm. No
code patching, no per-frame timing, no input handling.

**Hard candidates** patch *code*. Signs to look for in the ASI:

- Links `safetyhook`, `MinHook`, `Detours`, or similar. It installs trampolines,
  which means an arm64 equivalent has to be written from scratch.
- Imports `XINPUT1_4.dll` or `HID.DLL`. It reads controllers. On macOS this is
  actually easier — `GameController.framework` handles Xbox and DualSense
  natively over USB and Bluetooth — but it is still a subsystem to build.
- Contains a named shared memory handle. It coordinates with other mods and
  depends on a pointer handshake.
- Writes struct fields through a pointer chain rather than to fixed addresses.
  Then object layout has to be recovered, not just an address.

A worked triage: `EnhancedFlight.asi` links `safetyhook`, imports both XInput
and HID, and reads the player object through
`CrimsonDesert_PlayerBase_SharedMem_Bambozu`. It is portable in principle, but
it is a project rather than an afternoon, and the constant-fingerprint trick does
not apply because there is no vanilla value pair to search for.

## Useful commands

```sh
# Disassemble a Windows ASI on macOS
objdump -d Mod.asi > mod.asm

# Find float comparisons, which is where validation constants surface
rg 'u?comiss' mod.asm

# Read the constants out of .rdata
objdump -s -j .rdata Mod.asi

# Inspect the Mac game binary
nm -U /Applications/CrimsonDesert.app/Contents/MacOS/CrimsonDesert
strings -a /Applications/CrimsonDesert.app/Contents/MacOS/CrimsonDesert
```

Note that the Crimson Desert Mac binary is unstripped and retains mangled `pa::`
C++ symbols, which makes symbol-anchored work far more pleasant than usual.
