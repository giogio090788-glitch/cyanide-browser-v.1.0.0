#ifndef ADBLOCK_H
#define ADBLOCK_H

#include <glib.h>
#include <webkit2/webkit2.h>

/* Simple domain-based tracker blocker.
 * Uses a GHashTable for O(1) domain lookups plus a list of path-patterns. */
typedef struct {
    GHashTable *domains;        /* exact/suffix domain matching */
    GPtrArray  *path_patterns;  /* patterns that include path segments */
    guint       blocked_total;
} AdBlocker;

AdBlocker *adblock_new       (void);
void       adblock_free      (AdBlocker *ab);
gboolean   adblock_should_block (AdBlocker *ab, const char *uri);
void       adblock_load_file (AdBlocker *ab, const char *path);

/* Generate a WebKit Content Filter JSON string from the blocklist.
 * Caller must g_free() the returned string. */
char *adblock_make_filter_json (AdBlocker *ab);

#endif /* ADBLOCK_H */
