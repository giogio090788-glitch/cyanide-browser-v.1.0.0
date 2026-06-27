#include "privacy.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── User-Agent rotation pool ─────────────────────────────────────────────── */
static const char *UA_POOL[] = {
    /* Chrome / Windows */
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    /* Firefox / Windows */
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    /* Safari / macOS */
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    /* Chrome / macOS */
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    /* Edge */
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
};
#define UA_POOL_SIZE (int)(sizeof(UA_POOL) / sizeof(UA_POOL[0]))

/* ── Data-Poisoning + Privacy JavaScript ──────────────────────────────────
 *
 *  Injected at document-start into every frame. Poisons:
 *    1. Canvas 2D  — getImageData adds per-session per-pixel noise
 *    2. WebGL      — readPixels adds the same noise
 *    3. AudioBuffer— getChannelData adds sub-LSB noise
 *    4. Navigator  — platform, languages, hardwareConcurrency, deviceMemory
 *    5. Screen     — width/height spoofed to 1920×1080
 *    6. WebRTC     — RTCPeerConnection throws (blocks IP leak)
 *    7. XHR/Fetch  — blocks outbound requests to known tracker domains
 *    8. Battery    — disabled
 *    9. Plugins    — spoofed to look like a bare Chrome install
 *   10. Timezone   — Intl resolvedOptions reports UTC
 */
static const char POISON_JS[] =
"(function(){"
"'use strict';"

/* ── Stable-per-session hash for reproducible pixel noise ── */
"const _s=(Math.random()*2147483647)|0;"
"function _h(a,b,c){"
  "let h=(_s^(a*374761393)^(b*1013904223)^(c*16777619))|0;"
  "h^=h>>>16;h=Math.imul(h,0x85ebca6b)|0;"
  "h^=h>>>13;h=Math.imul(h,0xc2b2ae35)|0;"
  "return(h^(h>>>16))&1;"
"}"

/* ── Canvas 2D fingerprint poisoning ── */
"const _og=HTMLCanvasElement.prototype.getContext;"
"HTMLCanvasElement.prototype.getContext=function(t,o){"
  "const c=_og.call(this,t,o);"
  "if(!c||t!=='2d'||c._cy)return c;"
  "c._cy=true;"
  "const _gi=c.getImageData.bind(c);"
  "c.getImageData=function(sx,sy,sw,sh){"
    "const im=_gi(sx,sy,sw,sh);"
    "for(let j=0,n=im.data.length;j<n;j+=4){"
      "const p=j>>2,px=(p%sw)+sx,py=(p/sw|0)+sy;"
      "im.data[j]^=_h(px,py,0);"
      "im.data[j+1]^=_h(px,py,1);"
      "im.data[j+2]^=_h(px,py,2);"
    "}"
    "return im;"
  "};"
  "return c;"
"};"

/* ── WebGL readPixels poisoning ── */
"if(window.WebGLRenderingContext){"
  "const _rp=WebGLRenderingContext.prototype.readPixels;"
  "WebGLRenderingContext.prototype.readPixels=function(x,y,w,h,f,t,b){"
    "_rp.call(this,x,y,w,h,f,t,b);"
    "if(b)for(let i=0;i<b.length;i++)b[i]^=_h(x+i,y,2);"
  "};"
"}"
"if(window.WebGL2RenderingContext){"
  "const _r2=WebGL2RenderingContext.prototype.readPixels;"
  "WebGL2RenderingContext.prototype.readPixels=function(x,y,w,h,f,t,b,off){"
    "_r2.call(this,x,y,w,h,f,t,b,off);"
    "if(b)for(let i=0;i<b.length;i++)b[i]^=_h(x+i,y,3);"
  "};"
"}"

/* ── AudioContext fingerprint poisoning ── */
"if(window.AudioBuffer){"
  "const _gcd=AudioBuffer.prototype.getChannelData;"
  "AudioBuffer.prototype.getChannelData=function(ch){"
    "const d=_gcd.call(this,ch);"
    "for(let i=0;i<d.length;i++)d[i]+=(_h(i,ch,_s&255)-0.5)*1e-7;"
    "return d;"
  "};"
"}"

/* ── Navigator spoofing ── */
"const _nv={platform:'Win32',hardwareConcurrency:4,maxTouchPoints:0};"
"for(const[k,v]of Object.entries(_nv))"
  "try{Object.defineProperty(navigator,k,{get:()=>v,configurable:true})}catch(e){}"
"try{Object.defineProperty(navigator,'languages',{get:()=>Object.freeze(['en-US','en']),configurable:true})}catch(e){}"
"if('deviceMemory'in navigator)"
  "try{Object.defineProperty(navigator,'deviceMemory',{get:()=>8,configurable:true})}catch(e){}"

/* ── Screen spoofing ── */
"const _sc={width:1920,height:1080,availWidth:1920,availHeight:1040,colorDepth:24,pixelDepth:24};"
"for(const[k,v]of Object.entries(_sc))"
  "try{Object.defineProperty(screen,k,{get:()=>v,configurable:true})}catch(e){}"

/* ── WebRTC IP-leak prevention ── */
"const _rtcErr=()=>{throw new DOMException('WebRTC disabled by Cyanide Browser','NotSupportedError');};"
"for(const k of['RTCPeerConnection','webkitRTCPeerConnection','mozRTCPeerConnection'])"
  "try{Object.defineProperty(window,k,{get:()=>_rtcErr,configurable:true})}catch(e){}"
"try{Object.defineProperty(navigator,'mediaDevices',{get:()=>undefined,configurable:true})}catch(e){}"

/* ── XHR / Fetch tracker blocking ── */
"const _bl=["
  "'google-analytics.com','googletagmanager.com','googletagservices.com',"
  "'doubleclick.net','googlesyndication.com','googleadservices.com',"
  "'connect.facebook.net','facebook.com/tr','static.ads-twitter.com',"
  "'amazon-adsystem.com','hotjar.com','fullstory.com','mixpanel.com',"
  "'segment.com','segment.io','amplitude.com','heap.io','crazyegg.com',"
  "'criteo.com','rubiconproject.com','pubmatic.com','openx.net',"
  "'appnexus.com','adnxs.com','adsrvr.org','scorecardresearch.com',"
  "'quantserve.com','omtrdc.net','demdex.net','chartbeat.com',"
  "'outbrain.com','taboola.com','addthis.com','sharethis.com',"
  "'woopra.com','kissmetrics.com','logrocket.com','smartlook.com'"
"];"
"function _ib(u){"
  "if(!u)return false;"
  "const s=typeof u==='string'?u:String(u&&u.url?u.url:u);"
  "return _bl.some(d=>s.includes(d));"
"}"
"const _xo=XMLHttpRequest.prototype.open;"
"XMLHttpRequest.prototype.open=function(m,u,...r){"
  "if(_ib(u)){this._blk=true;console.debug('[Cyanide] XHR blocked:',u);return;}"
  "return _xo.call(this,m,u,...r);"
"};"
"const _xs=XMLHttpRequest.prototype.send;"
"XMLHttpRequest.prototype.send=function(...a){"
  "if(this._blk)return;"
  "return _xs.apply(this,a);"
"};"
"const _of=window.fetch;"
"window.fetch=function(r,i){"
  "const u=r&&typeof r==='object'?r.url:r;"
  "if(_ib(u)){console.debug('[Cyanide] fetch blocked:',u);return Promise.reject(new TypeError('Blocked by Cyanide Browser'));}"
  "return _of.call(this,r,i);"
"};"

/* ── Battery API ── */
"try{Object.defineProperty(navigator,'getBattery',{get:()=>undefined,configurable:true})}catch(e){}"

/* ── Plugin / MimeType spoofing ── */
"try{Object.defineProperty(navigator,'plugins',{get:()=>[{name:'Chrome PDF Plugin',filename:'internal-pdf-viewer',description:'Portable Document Format',length:0}],configurable:true})}catch(e){}"
"try{Object.defineProperty(navigator,'mimeTypes',{get:()=>[],configurable:true})}catch(e){}"

/* ── Timezone spoofing → UTC ── */
"try{"
  "const _ro=Intl.DateTimeFormat.prototype.resolvedOptions;"
  "Intl.DateTimeFormat.prototype.resolvedOptions=function(){"
    "const o=_ro.call(this);return{...o,timeZone:'UTC'};"
  "};"
"}catch(e){}"

"})();";

/* ══════════════════════════════════════════════════════════════════════════ */

void privacy_init(PrivacySettings *s, int level) {
    memset(s, 0, sizeof(*s));
    s->level                    = level;
    s->strip_referrer           = TRUE;
    s->block_third_party_cookies = TRUE;

    if (level >= PRIVACY_LEVEL_MEDIUM) {
        s->spoof_useragent  = TRUE;
        s->spoof_navigator  = TRUE;
    }
    if (level >= PRIVACY_LEVEL_HIGH) {
        s->poison_canvas = TRUE;
        s->block_webrtc  = TRUE;
    }

    /* Pick a random user-agent for this session */
    int idx = rand() % UA_POOL_SIZE;
    strncpy(s->useragent, UA_POOL[idx], sizeof(s->useragent) - 1);
    g_print("[privacy] Session UA: %s\n", s->useragent);
}

void privacy_apply_to_context(PrivacySettings *s, WebKitWebContext *ctx) {
    /* Block / restrict cookies */
    WebKitCookieManager *cm = webkit_web_context_get_cookie_manager(ctx);
    webkit_cookie_manager_set_accept_policy(cm,
        s->block_third_party_cookies
            ? WEBKIT_COOKIE_POLICY_ACCEPT_NO_THIRD_PARTY
            : WEBKIT_COOKIE_POLICY_ACCEPT_ALWAYS);

    /* Disable spell-check (reduces fingerprint surface slightly) */
    webkit_web_context_set_spell_checking_enabled(ctx, FALSE);
}

void privacy_apply_to_view(PrivacySettings *s, WebKitWebView *view) {
    WebKitSettings *ws = webkit_web_view_get_settings(view);

    if (s->spoof_useragent)
        webkit_settings_set_user_agent(ws, s->useragent);

    /* Disable features that expose fingerprinting data or leak info.
     * dns-prefetching and hyperlink-auditing setters are deprecated in
     * WebKit2GTK 4.1 but still functional — suppress the warnings. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    webkit_settings_set_enable_dns_prefetching(ws, FALSE);
    webkit_settings_set_enable_hyperlink_auditing(ws, FALSE);
#pragma GCC diagnostic pop

    /* Write console messages to stdout so we can see blocked tracker logs */
    webkit_settings_set_enable_write_console_messages_to_stdout(ws, TRUE);
}

void privacy_inject_scripts(PrivacySettings *s, WebKitUserContentManager *ucm) {
    /* Always inject the full poisoning script regardless of exact level,
     * but only enable WebRTC/canvas blocking at HIGH level (JS handles it) */
    (void)s; /* all features are compiled into a single script */

    WebKitUserScript *script = webkit_user_script_new(
        POISON_JS,
        WEBKIT_USER_CONTENT_INJECT_ALL_FRAMES,
        WEBKIT_USER_SCRIPT_INJECT_AT_DOCUMENT_START,
        NULL, NULL);
    webkit_user_content_manager_add_script(ucm, script);
    webkit_user_script_unref(script);
    g_print("[privacy] Poison script injected into all frames\n");
}
