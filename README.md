# CrimsonLooker-Mac

A native `arm64` observation and modding runtime for **Crimson Desert on Apple
Silicon**.

Crimson Desert's modding ecosystem is built around Windows ASI plugins loaded by
Ultimate ASI Loader. Neither exists on macOS. CrimsonLooker is the Mac
equivalent: one dylib injected into the game process, doing two jobs.

## Two capabilities

### 1. Asset observation (the "Looker")

Interposes the file access calls the game makes — `open`, `openat`, `readdir`,
`stat` — and logs which assets it actually loads, when.

This is the part that is hard to get any other way. Static extraction tells you
what is *in* the PAZ archives; it cannot tell you which of several thousand
candidates the game reaches for when you equip a specific item, trigger a
specific ability, or enter a specific area. That mapping is what makes targeted
modding possible instead of guesswork.

Read-only. It observes calls and passes them through unchanged.

### 2. Axiom Force patching

Raises the reach and pull speed of the Abyss Gauntlet by writing two floats in
the running process:

| Value | Vanilla |
| --- | --- |
| Range | `20.0` |
| Pull speed | `40.0` |

No code patching, no trampolines, no file modification. Two `__DATA` writes.

If you only want this and would rather audit 1,300 lines than 3,800, it is
published separately as `AxiomForce-Mac`, which builds from a subset of these
same sources.

## What it never does

- Modify the game executable
- Modify `.paa` files, PAZ archives, or saves
- Patch code or install function hooks
- Touch the network

## Safety model

This program observes and writes into another program's memory, so it is built
to be boring and auditable.

**Build gating.** Patch addresses are absolute and valid for exactly one game
build, identified by Mach-O `LC_UUID`. On any other build the resolver refuses to
write and logs why. A game update disables the mod rather than turning it into a
random memory writer.

**Value verification.** Before writing, it confirms the target slots still hold
their expected vanilla values. A build that keeps its UUID but moves its data is
rejected.

**Fail closed.** Every failure path writes nothing. There is no best-guess mode.

**Bounded writes.** Writes are confined to `__DATA` ranges taken from the loaded
image's own load commands. Executable pages are refused outright.

**Observable.** Every write is logged with the value it replaced. A silent log
means nothing happened.

**Local signing.** `build.sh` applies an ad-hoc signature, trusted only on the
machine that produced it. That is intentional.

## Requirements

- Apple Silicon Mac
- Xcode command line tools (`xcode-select --install`)
- Crimson Desert, and something that injects a dylib into it

## Build

```sh
./build.sh
```

Output is `build/CrimsonLooker.dylib`. No third party dependencies; it links only
`libc++` and `libSystem`.

## Configuration

Everything is driven by environment variables, so nothing is hardcoded to any
particular install.

| Variable | Purpose |
| --- | --- |
| `CRIMSONLOOKER_LOG_PATH` | Absolute log path. Also decides where configs are looked for. |
| `CRIMSONLOOKER_REPORT_PATH` | JSON report output. |
| `CRIMSONLOOKER_CONTROL_PATH` | Control file polled for commands, used to start and stop capture. |
| `CRIMSONLOOKER_CAPTURE_DIR` | Where session captures are written. |
| `CRIMSONLOOKER_LOG_SYSTEM_FILES` | Include system file access in the log. Very noisy; off by default. |
| `CRIMSONLOOKER_RESEARCH_TRIGGER` | Arms the capture research path. |
| `CRIMSONLOOKER_AXIOM_CONFIG_PATH` | Explicit Axiom config path. |
| `CRIMSONLOOKER_AXIOM_SIGNATURE_PATH` | Explicit Axiom signature path. |
| `CRIMSONLOOKER_AXIOM_ENABLED` | Enable or disable Axiom patching. |
| `CRIMSONLOOKER_AXIOM_RANGE` | Range override. |
| `CRIMSONLOOKER_AXIOM_MAX_RANGE` | Upper bound accepted for range. |
| `CRIMSONLOOKER_AXIOM_MAX_PULL` | Upper bound accepted for pull speed. |
| `CRIMSONLOOKER_AXIOM_INI` | Read settings from a Windows-style INI instead of JSON. |
| `CRIMSONLOOKER_AXIOM_PROFILE` | Named settings profile. |

Templates for the Axiom config and the live tuning file are in `runtime/`.

## Verifying it worked

For asset observation, the log fills with game file paths as you play.

For Axiom, look for:

```text
[AxiomForce] override 0x10881926c 20 -> 250
```

The `20` matters more than the `250`. Reading back exactly the vanilla value is
what proves the right address was found rather than a plausible looking one.

If you see `resolver failed closed`, the addresses do not match your game build.
That is the expected, safe outcome after an update — see
[docs/PORTING.md](docs/PORTING.md).

## Porting other mods

`docs/PORTING.md` documents the technique that made the Axiom port work: recover
the *validation constants* a Windows ASI checks before binding, then scan Mach-O
`__DATA` for the same pattern, instead of trying to translate its offsets. It
also includes triage guidance for judging whether a given ASI mod is portable at
all, since some are afternoon projects and some are not.

## Next targets: loadouts and free flight

The next planned ports are intentionally narrower than a full Trinity port:

- read the exact currently equipped item instance in every equipment slot;
- prove how those instances move between inventory and equipment;
- recover one engine-native "equip this existing instance" operation;
- build verified save/apply loadouts on top of that operation;
- reproduce Trinity's airborne vertical-velocity Free Flight behavior on arm64.

The implementation order, acceptance tests, stop conditions, save-safety rules,
and proposed CDUMM/iOS bridge are documented in
[docs/LOADOUTS_AND_FLIGHT.md](docs/LOADOUTS_AND_FLIGHT.md).

Do not skip directly to equipment writes. The first loadout milestone is a
read-only equipment snapshot whose output changes predictably when exactly one
piece of gear is changed manually.

## License

MIT. See [LICENSE](LICENSE).
