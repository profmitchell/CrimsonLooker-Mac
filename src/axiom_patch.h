#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void start_axiom_patch_thread(void);
void axiom_set_capture_session_dir(const char *dir);
void axiom_record_calibration_snapshot(const char *label);
bool axiom_probe_remote_catch_component(void);

#ifdef __cplusplus
}
#endif
