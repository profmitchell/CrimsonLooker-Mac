# Loadouts and Free Flight roadmap

This document defines the next two CrimsonLooker targets after Axiom Force:

1. **Equipment loadouts** — capture the exact set of items currently equipped and later re-equip those same item instances on command.
2. **Free Flight** — port the semantics of Trinity's airborne locomotion override to Apple Silicon without copying Windows addresses or byte signatures.

The goal is not to port all of Trinity. The goal is to recover the smallest engine-native operations needed for these two features and expose them through CrimsonLooker's existing control/configuration layer.

Upstream reference project:

- Trinity: `https://github.com/XeTrinityz/Trinity`

## Design rule: evidence before interaction

Do not add a write, hook, or engine call until the immediately preceding read-only hypothesis is proven.

Every experiment must state three things before it is run:

1. **Invariant** — what specific engine fact is being tested.
2. **Success evidence** — the exact log/readback that proves the hypothesis.
3. **Failure evidence** — the result that disproves the hypothesis and forces a new approach.

Never repeat an unchanged manual test just because the previous test did not work. A retry is only justified if new telemetry or a changed hypothesis makes the result informative.

For user-facing testing, prefer one deliberate action per run. Example: "change Main Hand once" is better than cycling three weapons and trying to infer which memory change mattered.

## Why the old inventory approach was misleading

Trinity's reverse engineering shows that **worn equipment is not simply left in the ordinary inventory holder**.

The equipped item value lives in the player's equipment component while worn. When the engine replaces or removes an equipped item, the old item is copied back into an inventory bucket. This matters because searching the inventory holder for the instance ID of an item that is currently worn can correctly return nothing.

That means a loadout implementation must model two distinct states:

- item currently in an inventory/storage bucket;
- item currently resident in an equipment slot.

Do not treat the equipment table as a cosmetic mirror of inventory.

## Upstream facts worth porting semantically

The current Trinity source documents the following Windows-build facts. They are **semantic anchors**, not Mac offsets.

### Equipment snapshot

Trinity resolves an equipment component from the player character and walks a table containing the complete worn `TrItemValue` plus a slot tag.

The snapshot exposes at least:

- slot tag;
- item `typeId`;
- item `instanceId`;
- display name/icon;
- refinement level;
- socket state.

Known Trinity slot tags include:

| Tag | Slot |
| ---: | --- |
| 0 | Main Hand |
| 1 | Off-Hand |
| 2 | Ranged Weapon |
| 3 | Helmet |
| 4 | Chest |
| 5 | Gloves |
| 6 | Boots |
| 7 | Earring 1 |
| 8 | Earring 2 |
| 9 | Necklace |
| 10 | Ring 1 |
| 11 | Ring 2 |
| 12 | Dagger |
| 13 | Two-Handed Weapon |
| 15 | Lantern |
| 16 | Cloak |
| 17 | Glasses |
| 18 | Mask |
| 19 | Backpack |
| 20 | Bracelet |
| 21 | Rocket |

The first Mac milestone is only to recover the equivalent table and print it correctly.

### Engine-native equip path

Trinity identifies both a batch-equip function and a single-item equip path. The important behavior is that the engine moves complete item values between inventory and equipment rather than merely changing a `typeId` in place.

For CrimsonLooker, the desired final operation is therefore conceptually:

```text
equipExistingInstance(slotTag, instanceId)
```

not:

```text
writeTypeIdIntoEquipmentSlot(slotTag, typeId)
```

The latter is specifically the kind of shortcut that can create visually plausible but internally invalid state.

### Free Flight

Trinity's current Free Flight implementation hooks a locomotion sub-step where a mutable velocity vector is about to be passed to physics.

Its useful semantics are:

- identify the local player;
- only intervene in the airborne movement path;
- while Up is held, replace vertical velocity with `+flightSpeed`;
- while Down is held, replace vertical velocity with `-flightSpeed`;
- while neither (or both) is held, write nothing and let normal physics continue;
- do not convert normal jumps/aerial attacks into permanent hover state.

The Mac port should reproduce this behavior, not the Windows hook mechanics.

## Loadout data model

A saved loadout should prefer the exact item instance over only the base item type.

Suggested format:

```json
{
  "schema": 1,
  "name": "Black Set",
  "slots": [
    {
      "tag": 0,
      "typeId": 842,
      "instanceId": 1001734,
      "displayName": "example"
    },
    {
      "tag": 4,
      "typeId": 901,
      "instanceId": 1001811,
      "displayName": "example"
    }
  ]
}
```

`instanceId` is the primary identity. `typeId` and `displayName` are useful for diagnostics and future recovery if a save migration changes instance IDs.

Do **not** silently substitute another copy of the same `typeId` in the first implementation. Report that the saved instance is missing. Automatic fallback can be added later when the matching rules are understood well enough to avoid choosing the wrong refined/dyed/socketed copy.

## Milestone 1 — read current equipment

**No writes. No hooks unless a read-only hook is the only way to obtain the component.**

Implement an `equipment_probe` module that can produce a stable snapshot of the currently equipped set.

Minimum output per slot:

```text
[Equipment] tag=4 slot=Chest typeId=901 instanceId=1001811
```

Recommended additional diagnostic fields when cheaply available:

- raw equipment component address;
- table descriptor address;
- table count;
- raw entry address;
- refinement level;
- engine key/display name.

### Acceptance test

1. Launch with probe enabled.
2. Capture snapshot A.
3. Manually replace **one** known slot, e.g. Main Hand.
4. Capture snapshot B.
5. Exactly the changed slot must show the new item identity while unrelated slots remain stable.
6. Change back and verify the original instance returns.

If this test does not pass, do not implement loadout persistence or equip writes yet.

## Milestone 2 — prove movement between equipment and inventory

Still read-only.

Choose one exact item instance and observe it before and after a manual equip/unequip operation.

The expected model is:

```text
before equip: instance is in an inventory bucket
while equipped: instance is in the equipment table
when replaced: displaced equipped instance returns to a bucket
```

The important output is instance identity, not just item type.

### Acceptance test

A single manual equip action produces a coherent before/after trace showing the old and new instances changing homes exactly once.

If an instance appears duplicated in both ordinary inventory and equipment, treat that as evidence that the current structure interpretation is wrong before writing anything.

## Milestone 3 — locate the Mac equip operation

Use Trinity's documented equip path as a semantic target, but derive the Apple Silicon implementation independently.

Good anchors include:

- retained `pa::` symbols in the Mac executable;
- functions that consume the recovered equipment component;
- call sites triggered by one manual equip action;
- complete-item copy/move operations;
- the transition that returns the displaced item to a bucket.

Prefer tracing from the already-proven equipment structure outward over broad scans of arbitrary inventory functions.

For every candidate function, document:

```text
Candidate:
Why it might be equip:
Expected arguments:
Read-only evidence:
What would falsify it:
```

Do not call an unknown candidate merely because it runs near an equip event.

## Milestone 4 — one automated equipment swap

Only after Milestones 1–3 are proven.

Queue one request for one known inventory item instance and one known compatible slot. Dispatch on the game thread if the engine operation requires it.

A successful request must satisfy all of these:

1. Requested instance becomes the equipped instance in the requested slot.
2. The displaced instance leaves the equipment table.
3. The displaced instance appears in the appropriate inventory/storage state.
4. The rendered character updates.
5. A fresh readback agrees with the request.
6. Save/reload behavior is tested separately before claiming persistence.

Do not report success based only on the character visually changing.

## Milestone 5 — save/apply loadouts

Once one native swap is reliable:

### Save

- snapshot every occupied equipment slot;
- store slot tag + `instanceId` + diagnostic metadata;
- persist outside the game save, e.g. CrimsonLooker/CDUMM application support JSON.

### Apply

For each saved slot:

1. resolve the saved instance in current live state;
2. confirm it is compatible/available;
3. request engine-native equip;
4. wait for readback confirmation;
5. only then proceed to the next slot.

A loadout application should be a sequence of verified transactions rather than a burst of blind writes.

Suggested status model:

```text
Idle -> Resolving -> Equipping(slot N) -> Verifying(slot N) -> Complete
                                      \-> Failed(reason)
```

Partial application should return a structured result showing which slots succeeded, failed, or were skipped.

## Companion-app bridge

Keep phone/macOS UI communication outside the dylib's game-memory logic.

Suggested architecture:

```text
iOS companion
    -> local CDUMM endpoint
        -> command/config file or local IPC
            -> CrimsonLooker runtime
                -> equipment service
                    -> game-thread request queue
```

Useful commands:

```json
{ "command": "equipment.snapshot" }
{ "command": "loadout.save", "name": "Black Set" }
{ "command": "loadout.apply", "id": "black-set" }
{ "command": "flight.setEnabled", "value": true }
{ "command": "flight.setSpeed", "value": 8.0 }
```

The network/UI layer must never accept raw memory addresses from the client. Expose semantic commands only.

## Free Flight milestones

### Flight 1 — identify locomotion callback

Find the Mac function corresponding to the semantic point Trinity hooks: a player locomotion step with a mutable movement/velocity vector.

Prove it read-only by logging bounded samples only for the local player.

Acceptance evidence should correlate with deliberate actions:

- standing still;
- walking forward;
- jumping;
- falling/gliding.

Do not patch anything during this stage.

### Flight 2 — identify airborne context

Find a reliable predicate or call-site identity that distinguishes the airborne movement path from grounded locomotion.

A candidate is accepted only if logs show:

- grounded movement rejected;
- ordinary airborne movement accepted;
- NPC movement rejected.

### Flight 3 — vertical velocity override

Add the smallest possible guarded write:

```text
if localPlayer && airborne && exactlyOne(up, down):
    verticalVelocity = up ? +speed : -speed
else:
    write nothing
```

Use a conservative initial speed. Extreme values are bad diagnostics because the game may clamp or reject them.

### Flight 4 — input/configuration

Keep the first implementation controllable through CrimsonLooker configuration/control commands. Native `GameController.framework` input can be added afterward if useful.

This makes the physics port testable independently from keyboard/controller integration.

## Stop conditions

Stop an experiment and change strategy when any of these happen:

- the expected invariant fails twice with identical instrumentation;
- the candidate produces state changes unrelated to the one manual action being tested;
- a pointer/entry cannot be self-validated;
- an operation requires fabricated item state instead of moving an existing engine item;
- a test crashes or corrupts a save;
- the only argument for continuing is that an address/value "looks plausible."

After a failure, preserve the log and add a short note explaining what was disproven. Failed approaches are useful project knowledge and should not be rediscovered later.

## Save safety

Inventory/equipment experimentation is higher risk than Axiom's static float patch.

Until the engine-native equip transaction is understood:

- do not create inventory items by manually fabricating slot records;
- do not write arbitrary item values into the equipment table;
- do not edit save files;
- do not run destructive tests on the only copy of a valued save;
- keep automatic cloud-save behavior conceptually separate from runtime injection.

CrimsonLooker loadout definitions should remain local app data. A loadout is a set of references to items in the user's game state, not a replacement game save.

## Future loader architecture

A `.dylib` does not load merely because it is placed next to the game executable or somewhere inside the app bundle. Something already executing in the process must load it.

Today CrimsonLooker therefore still depends on an injector/bootstrap such as CDUMM.

A future Mac ASI-like architecture could use one stable injected runtime as a plugin host:

```text
CrimsonRuntime.dylib
    -> dlopen(".../Plugins/AxiomForce.dylib")
    -> dlopen(".../Plugins/Loadouts.dylib")
    -> dlopen(".../Plugins/FreeFlight.dylib")
```

Prefer an external application-support directory such as:

```text
~/Library/Application Support/CrimsonLooker/Plugins/
```

over modifying the signed game bundle for every plugin.

Plugin loading, signing, and storefront compatibility should be treated as a separate subsystem from game-feature reverse engineering. A working equipment probe should not depend on solving generalized plugin distribution first.
