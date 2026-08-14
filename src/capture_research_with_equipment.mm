// Integration shim: preserve the existing CrimsonLooker startup sequence while
// starting the read-only equipment probe from the same call site.
//
// CrimsonLooker.mm already calls start_capture_research_thread() from its one
// established dylib constructor. Rather than add a second constructor or touch
// the large, known-working startup file, compile capture_research.mm through
// this shim, rename its original starter, and expose a tiny wrapper that starts
// both background readers.

#define start_capture_research_thread crimsonlooker_start_capture_research_thread_impl
#include "capture_research.mm"
#undef start_capture_research_thread

#include "equipment_probe.h"

extern "C" void start_capture_research_thread(void) {
    crimsonlooker_start_capture_research_thread_impl();
    start_equipment_probe_thread();
}
