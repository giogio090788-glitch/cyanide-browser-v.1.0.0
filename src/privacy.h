#ifndef PRIVACY_H
#define PRIVACY_H

#include <webkit2/webkit2.h>
#include <glib.h>

/* Privacy levels */
#define PRIVACY_LEVEL_LOW    1   /* Block 3rd-party cookies, strip referrer */
#define PRIVACY_LEVEL_MEDIUM 2   /* + UA spoofing, navigator overrides */
#define PRIVACY_LEVEL_HIGH   3   /* + canvas/WebGL poisoning, WebRTC block */

typedef struct {
    int      level;
    gboolean spoof_useragent;
    gboolean poison_canvas;        /* Canvas + WebGL fingerprint noise */
    gboolean block_webrtc;         /* Prevent IP leaks via WebRTC */
    gboolean strip_referrer;
    gboolean block_third_party_cookies;
    gboolean spoof_navigator;      /* Platform, languages, hwConcurrency */
    char     useragent[512];
} PrivacySettings;

void privacy_init             (PrivacySettings *s, int level);
void privacy_apply_to_context (PrivacySettings *s, WebKitWebContext *ctx);
void privacy_apply_to_view    (PrivacySettings *s, WebKitWebView *view);
void privacy_inject_scripts   (PrivacySettings *s, WebKitUserContentManager *ucm);

#endif /* PRIVACY_H */
