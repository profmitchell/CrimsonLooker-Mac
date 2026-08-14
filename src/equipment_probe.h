#pragma once

// Starts the read-only equipment discovery probe on a detached background
// thread. The probe never writes game memory and never installs a hook.
void start_equipment_probe_thread();

// Returns the path selected for the probe log. The implementation prefers the
// user's Desktop, then falls back beside CRIMSONLOOKER_LOG_PATH, then /tmp.
const char *equipment_probe_log_path();
