# Equipment probe — one-run test

This is the first runtime milestone for the loadout project. The test is deliberately read-only: it does not equip anything, edit inventory, patch game code, touch the save, or install a hook.

## What the probe is testing

The current Trinity source documents the Windows build's equipped-item data layout in unusually strong detail. The probe does **not** reuse Trinity's Windows byte signatures or addresses. Instead it tests whether the native Apple Silicon build kept the same 64-bit data relationships:

- equipment table descriptor: `+0x08 -> entry array`, `+0x10 -> count`
- equipped entry stride: `0xC8`
- item instance ID: entry `+0x00`
- item type ID: entry `+0x08`
- quantity: entry `+0x10`
- equipment slot tag: entry `+0xC0`
- equipment component: `+0x88 -> descriptor`
- component: `+0x08 -> owner`
- owner: `+0x68 -> sub-object`
- sub-object: `+0x38 -> same equipment component`

That last round-trip is the important independent validation. A candidate is not called resolved merely because some memory happens to resemble item IDs.

## Build

On the probe branch:

```sh
git fetch origin
git switch agent/loadouts-flight-roadmap
./build.sh
```

Use:

```text
build/CrimsonLooker.dylib
```

The build remains arm64 and ad-hoc signed exactly like the existing working CrimsonLooker build.

## Test

1. Replace the CrimsonLooker dylib that CDUMM currently injects with the newly built `build/CrimsonLooker.dylib`.
2. Launch Crimson Desert normally through the same working CDUMM/injection setup.
3. Load your normal single-player save and get fully into the world.
4. Play normally. The probe waits 20 seconds before its first pass and retries automatically if the player/equipment objects were not ready yet.
5. Once in-world, change **one obvious equipped item once** — for example helmet A -> helmet B or weapon A -> weapon B. You do not need to swap it repeatedly.
6. Keep playing briefly. If the table resolves, the probe watches it and logs a new snapshot automatically when equipped state changes.
7. Quit normally and inspect/send `CrimsonLooker-EquipmentProbe.log`.

No trigger file, menu, button, terminal command, or inventory calibration pickup is required after launch.

## Log location

If CDUMM supplies `CRIMSONLOOKER_LOG_PATH`, the probe file is written beside that normal CrimsonLooker log as:

```text
CrimsonLooker-EquipmentProbe.log
```

Otherwise it falls back to:

```text
/tmp/CrimsonLooker-EquipmentProbe.log
```

The exact path is not part of the experiment; the evidence inside the file is.

## How to read the result

### `*** SUCCESS: READ-ONLY EQUIPMENT MILESTONE PASSED ***`

Best result. The probe found an equipment-shaped table **and** recovered an object that satisfies the component -> owner -> sub-object -> same-component round-trip. The log then prints every table entry with:

- slot tag / human-readable slot label
- type ID
- instance ID
- quantity
- subtype/refinement field
- live entry address

It continues watching the resolved descriptor and prints `EQUIPMENT SNAPSHOT CHANGED` when gear changes.

**Next step:** stop discovery work and implement a small stable equipment-reader API around this recovered chain. Do not start writing equipment yet.

### `EQUIPMENT-LIKE TABLE(S) FOUND, but no component passed...`

Still useful. It suggests the `TrItemValue + tag` table layout survived Windows -> arm64, but one or more component relationship offsets (`+0x88`, owner `+0x08`, owner/sub `+0x68/+0x38`) differ.

**Next step:** use the logged table/descriptor addresses as anchors to recover the arm64 component relationship. Do not repeat the unchanged game test.

### `NO EQUIPMENT-TABLE CANDIDATE`

If this appears on an early pass while still loading, ignore it; the probe retries automatically. If all six passes finish with no candidate while the player was definitely in-world, that is evidence that at least one of the table assumptions differs on arm64 (descriptor layout, `0xC8` stride, item fields, or slot-tag offset).

**Next step:** change the reverse-engineering hypothesis, not the number of times the user swaps a sword.

## Stop rule

Do not ask the tester to repeat an unchanged manual action because a result was disappointing. Every follow-up experiment must state:

1. which specific assumption it changes,
2. what telemetry it adds,
3. what output would confirm it, and
4. what output would reject it.

The point of this probe is to turn one normal play session into enough evidence for the next engineering decision.
