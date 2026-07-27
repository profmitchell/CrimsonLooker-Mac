#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void capture_research_note_path(const char *path);
void capture_research_set_session_dir(const char *dir);
void start_capture_research_thread(void);

#ifdef __cplusplus
}
#endif
