#include "adblock.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ── Built-in tracker / ad domain list ──────────────────────────────────── */
static const char *BUILTIN[] = {
    /* Google advertising & analytics */
    "google-analytics.com",
    "googletagmanager.com",
    "googletagservices.com",
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "stats.g.doubleclick.net",
    "adservice.google.com",
    /* Facebook */
    "connect.facebook.net",
    "graph.facebook.com",
    /* Amazon ads */
    "amazon-adsystem.com",
    /* Twitter/X ads */
    "ads-twitter.com",
    "static.ads-twitter.com",
    "t.co",
    /* LinkedIn */
    "snap.licdn.com",
    /* Analytics & session recording */
    "scorecardresearch.com",
    "quantserve.com",
    "omtrdc.net",
    "demdex.net",
    "chartbeat.com",
    "hotjar.com",
    "fullstory.com",
    "mouseflow.com",
    "crazyegg.com",
    "logrocket.com",
    "smartlook.com",
    "clicktale.net",
    "inspectlet.com",
    /* Product analytics */
    "mixpanel.com",
    "segment.com",
    "segment.io",
    "amplitude.com",
    "heap.io",
    "woopra.com",
    "kissmetrics.com",
    "clicky.com",
    /* Social / sharing widgets */
    "addthis.com",
    "sharethis.com",
    "platform.twitter.com",
    /* Outbrain / Taboola (content ads) */
    "outbrain.com",
    "taboola.com",
    /* Programmatic ad networks */
    "criteo.com",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "appnexus.com",
    "adnxs.com",
    "adsrvr.org",
    "advertising.com",
    "turn.com",
    "casalemedia.com",
    "contextweb.com",
    "spotxchange.com",
    "mathtag.com",
    "tidaltv.com",
    "mediaplex.com",
    "sizmek.com",
    "smartadserver.com",
    "undertone.com",
    /* Tracking CDNs */
    "cdn.mxpnl.com",
    "cdn.branch.io",
    /* Misc */
    "imrworldwide.com",
    "newrelic.com",
    "nr-data.net",
    "datadog-browser-agent.com",
    NULL
};

/* Path-based patterns (need strstr on full URI) */
static const char *PATH_PATTERNS[] = {
    "google.com/pagead",
    "google.com/ads",
    "youtube.com/pagead",
    "facebook.com/tr",
    NULL
};

/* ──────────────────────────────────────────────────────────────────────── */

AdBlocker *adblock_new(void) {
    AdBlocker *ab = g_new0(AdBlocker, 1);
    ab->domains = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    ab->path_patterns = g_ptr_array_new_with_free_func(g_free);

    for (int i = 0; BUILTIN[i]; i++)
        g_hash_table_insert(ab->domains, g_strdup(BUILTIN[i]), GINT_TO_POINTER(1));

    for (int i = 0; PATH_PATTERNS[i]; i++)
        g_ptr_array_add(ab->path_patterns, g_strdup(PATH_PATTERNS[i]));

    g_print("[adblock] Loaded %u built-in domains\n",
            g_hash_table_size(ab->domains));
    return ab;
}

void adblock_free(AdBlocker *ab) {
    if (!ab) return;
    g_hash_table_destroy(ab->domains);
    g_ptr_array_free(ab->path_patterns, TRUE);
    g_free(ab);
}

/* Extract hostname from a URI (returned pointer into uri, not heap-allocated) */
static gboolean uri_matches_domain(const char *uri, const char *domain) {
    /* Find start of host after scheme:// */
    const char *host = strstr(uri, "://");
    if (!host) return FALSE;
    host += 3;

    /* Find end of host */
    const char *end = host;
    while (*end && *end != '/' && *end != ':' && *end != '?') end++;

    gsize host_len = (gsize)(end - host);
    gsize dom_len  = strlen(domain);

    if (host_len == 0 || dom_len == 0) return FALSE;

    /* Exact match */
    if (host_len == dom_len && strncmp(host, domain, dom_len) == 0) return TRUE;

    /* Suffix match: host ends with ".domain" */
    if (host_len > dom_len + 1 &&
        host[host_len - dom_len - 1] == '.' &&
        strncmp(host + host_len - dom_len, domain, dom_len) == 0)
        return TRUE;

    return FALSE;
}

gboolean adblock_should_block(AdBlocker *ab, const char *uri) {
    if (!ab || !uri || *uri == '\0') return FALSE;

    /* Skip about: and data: URIs */
    if (g_str_has_prefix(uri, "about:") || g_str_has_prefix(uri, "data:"))
        return FALSE;

    /* Domain lookup */
    GHashTableIter it;
    gpointer key;
    g_hash_table_iter_init(&it, ab->domains);
    while (g_hash_table_iter_next(&it, &key, NULL)) {
        if (uri_matches_domain(uri, (const char *)key)) {
            ab->blocked_total++;
            return TRUE;
        }
    }

    /* Path-pattern lookup */
    for (guint i = 0; i < ab->path_patterns->len; i++) {
        const char *pat = g_ptr_array_index(ab->path_patterns, i);
        if (strstr(uri, pat)) {
            ab->blocked_total++;
            return TRUE;
        }
    }

    return FALSE;
}

void adblock_load_file(AdBlocker *ab, const char *path) {
    if (!ab || !path) return;
    FILE *f = fopen(path, "r");
    if (!f) {
        g_print("[adblock] Could not open %s — using built-in list only\n", path);
        return;
    }
    char line[512];
    int  count = 0;
    while (fgets(line, sizeof(line), f)) {
        gsize len = strlen(line);
        while (len > 0 && (line[len-1]=='\n'||line[len-1]=='\r'||line[len-1]==' '))
            line[--len] = '\0';
        if (len == 0 || line[0] == '#' || line[0] == '!')
            continue;
        if (!g_hash_table_contains(ab->domains, line)) {
            g_hash_table_insert(ab->domains, g_strdup(line), GINT_TO_POINTER(1));
            count++;
        }
    }
    fclose(f);
    g_print("[adblock] +%d domains from %s\n", count, path);
}

/* Build a WebKit Content Filter JSON (WKContentRuleList format).
 * This blocks network-level requests including <script>, <img>, etc. */
char *adblock_make_filter_json(AdBlocker *ab) {
    GString *json = g_string_new("[");
    gboolean first = TRUE;

    GHashTableIter it;
    gpointer key;
    g_hash_table_iter_init(&it, ab->domains);
    while (g_hash_table_iter_next(&it, &key, NULL)) {
        const char *dom = (const char *)key;
        if (!first) g_string_append_c(json, ',');
        first = FALSE;
        /* url-filter is a regex; escape dots */
        GString *pattern = g_string_new("");
        for (const char *p = dom; *p; p++) {
            if (*p == '.') g_string_append(pattern, "\\.");
            else           g_string_append_c(pattern, *p);
        }
        g_string_append_printf(json,
            "{\"trigger\":{\"url-filter\":\"%s\"},"
            "\"action\":{\"type\":\"block\"}}",
            pattern->str);
        g_string_free(pattern, TRUE);
    }

    /* Path-based patterns */
    for (guint i = 0; i < ab->path_patterns->len; i++) {
        const char *pat = g_ptr_array_index(ab->path_patterns, i);
        if (!first) g_string_append_c(json, ',');
        first = FALSE;
        g_string_append_printf(json,
            "{\"trigger\":{\"url-filter\":\"%s\"},"
            "\"action\":{\"type\":\"block\"}}",
            pat);
    }

    g_string_append_c(json, ']');
    return g_string_free(json, FALSE);
}
