/*
 * Cyanide Browser — Privacy-first web browser with data poisoning
 *
 * Features
 * --------
 *  - Ephemeral tabbed browsing (GtkNotebook)
 *  - Ephemeral session (no persistent history, cookies, or cache)
 *  - Canvas / WebGL fingerprint poisoning (per-session random noise)
 *  - User-Agent rotation on every launch
 *  - Navigator / Screen property spoofing
 *  - WebRTC IP-leak prevention
 *  - AudioContext fingerprint poisoning
 *  - XHR / Fetch tracker blocking (JS layer)
 *  - Network-level tracker blocking via WebKit Content Filter
 *  - Third-party cookie blocking
 *  - DuckDuckGo as default search engine
 */

#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <webkit2/webkit2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "privacy.h"
#include "adblock.h"

#define CYANIDE_VERSION  "1.0.0"
#define WINDOW_W         1280
#define WINDOW_H         820
#define FILTER_STORE_DIR "/tmp/cyanide-filter-store"
#define TAB_TITLE_MAX    22   /* chars before truncation in tab strip */

/* ── Per-tab state ───────────────────────────────────────────────────────── */
typedef struct {
    WebKitWebView *view;
    GtkWidget     *tab_box;    /* HBox shown inside the notebook tab label  */
    GtkWidget     *title_lbl;  /* truncated page title in the tab strip     */
    guint          blocked;    /* requests blocked for this tab             */
    gboolean       is_loading;
} CyanideTab;

/* ── Application state ──────────────────────────────────────────────────── */
typedef struct {
    GtkWidget              *window;
    GtkWidget              *back_btn;
    GtkWidget              *fwd_btn;
    GtkWidget              *reload_btn;
    GtkWidget              *reload_img;
    GtkWidget              *url_entry;
    GtkWidget              *status_bar;
    GtkWidget              *shield_label;
    GtkWidget              *menu_btn;
    GtkWidget              *menu_popover;
    GtkWidget              *progress_bar;
    GtkWidget              *notebook;
    GPtrArray              *tabs;
    WebKitWebContext       *ctx;
    WebKitUserContentManager *ucm;
    PrivacySettings         privacy;
    AdBlocker              *adblock;
} CyanideApp;

static CyanideApp app;

/* ── Forward declarations ────────────────────────────────────────────────── */
static void        tab_new     (const char *url);
static void        tab_close   (CyanideTab *tab);
static CyanideTab *tab_current (void);
static const char *START_HTML_PTR;

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static char *canonicalize_input(const char *raw) {
    if (!raw || *raw == '\0') return g_strdup("about:blank");
    if (g_str_has_prefix(raw, "http://")  ||
        g_str_has_prefix(raw, "https://") ||
        g_str_has_prefix(raw, "about:")   ||
        g_str_has_prefix(raw, "file://"))
        return g_strdup(raw);
    if (strchr(raw, '.') && !strchr(raw, ' '))
        return g_strdup_printf("https://%s", raw);
    char *enc = g_uri_escape_string(raw, NULL, FALSE);
    char *url = g_strdup_printf("https://duckduckgo.com/?q=%s", enc);
    g_free(enc);
    return url;
}

static CyanideTab *tab_current(void) {
    if (!app.notebook || !app.tabs) return NULL;
    int idx = gtk_notebook_get_current_page(GTK_NOTEBOOK(app.notebook));
    if (idx < 0 || (guint)idx >= app.tabs->len) return NULL;
    return g_ptr_array_index(app.tabs, (guint)idx);
}

static void navigate(const char *input) {
    CyanideTab *tab = tab_current();
    if (!tab) return;
    char *url = canonicalize_input(input);
    webkit_web_view_load_uri(tab->view, url);
    g_free(url);
}

static void update_shield(void) {
    CyanideTab *tab = tab_current();
    guint n = tab ? tab->blocked : 0;
    char *txt = g_strdup_printf(
        "<span foreground='#a6e3a1' font='Inter, Segoe UI, sans-serif 9'>"
        " \xe2\x9a\x97  %u blocked</span>", n);
    gtk_label_set_markup(GTK_LABEL(app.shield_label), txt);
    g_free(txt);
}

static void update_security_icon(const char *uri) {
    if (!uri || *uri == '\0' || g_str_has_prefix(uri, "about:")) {
        gtk_entry_set_icon_from_icon_name(
            GTK_ENTRY(app.url_entry), GTK_ENTRY_ICON_PRIMARY,
            "dialog-question-symbolic");
        gtk_entry_set_icon_tooltip_text(
            GTK_ENTRY(app.url_entry), GTK_ENTRY_ICON_PRIMARY, NULL);
        return;
    }
    if (g_str_has_prefix(uri, "https://")) {
        gtk_entry_set_icon_from_icon_name(
            GTK_ENTRY(app.url_entry), GTK_ENTRY_ICON_PRIMARY,
            "channel-secure-symbolic");
        gtk_entry_set_icon_tooltip_text(
            GTK_ENTRY(app.url_entry), GTK_ENTRY_ICON_PRIMARY,
            "Secure connection (HTTPS)");
    } else if (g_str_has_prefix(uri, "http://")) {
        gtk_entry_set_icon_from_icon_name(
            GTK_ENTRY(app.url_entry), GTK_ENTRY_ICON_PRIMARY,
            "channel-insecure-symbolic");
        gtk_entry_set_icon_tooltip_text(
            GTK_ENTRY(app.url_entry), GTK_ENTRY_ICON_PRIMARY,
            "Insecure connection \xe2\x80\x94 avoid entering private data");
    } else {
        gtk_entry_set_icon_from_icon_name(
            GTK_ENTRY(app.url_entry), GTK_ENTRY_ICON_PRIMARY,
            "text-html-symbolic");
        gtk_entry_set_icon_tooltip_text(
            GTK_ENTRY(app.url_entry), GTK_ENTRY_ICON_PRIMARY, NULL);
    }
}

/* Sync toolbar state from a given tab (call after tab switches). */
static void toolbar_sync(CyanideTab *tab) {
    if (!tab) return;
    const char *uri = webkit_web_view_get_uri(tab->view);

    /* URL bar */
    gtk_entry_set_text(GTK_ENTRY(app.url_entry), uri ? uri : "");
    update_security_icon(uri);

    /* Nav buttons */
    gtk_widget_set_sensitive(app.back_btn,
        webkit_web_view_can_go_back(tab->view));
    gtk_widget_set_sensitive(app.fwd_btn,
        webkit_web_view_can_go_forward(tab->view));

    /* Reload / stop button */
    if (tab->is_loading) {
        gtk_image_set_from_icon_name(GTK_IMAGE(app.reload_img),
            "process-stop-symbolic", GTK_ICON_SIZE_SMALL_TOOLBAR);
        gtk_widget_set_tooltip_text(app.reload_btn, "Stop loading  (Esc)");
        gtk_widget_show(app.progress_bar);
        double p = webkit_web_view_get_estimated_load_progress(tab->view);
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app.progress_bar), p);
        char *txt = g_strdup("<span foreground='#f9e2af' "
            "font='Inter, Segoe UI, sans-serif 9'>"
            " \xe2\x9a\x97  loading\xe2\x80\xa6</span>");
        gtk_label_set_markup(GTK_LABEL(app.shield_label), txt);
        g_free(txt);
    } else {
        gtk_image_set_from_icon_name(GTK_IMAGE(app.reload_img),
            "view-refresh-symbolic", GTK_ICON_SIZE_SMALL_TOOLBAR);
        gtk_widget_set_tooltip_text(app.reload_btn, "Reload page  (F5)");
        gtk_widget_hide(app.progress_bar);
        update_shield();
    }

    /* Window title */
    const char *title = webkit_web_view_get_title(tab->view);
    if (title && *title) {
        char *t = g_strdup_printf("Cyanide \xe2\x80\x94 %s", title);
        gtk_window_set_title(GTK_WINDOW(app.window), t);
        g_free(t);
    } else {
        gtk_window_set_title(GTK_WINDOW(app.window), "Cyanide Browser");
    }
}

/* ── Signal handlers ─────────────────────────────────────────────────────── */

static void on_url_activate(GtkEntry *e, gpointer _) {
    (void)_;
    navigate(gtk_entry_get_text(e));
}

static void on_back(GtkButton *_, gpointer __) {
    (void)_; (void)__;
    CyanideTab *tab = tab_current();
    if (tab && webkit_web_view_can_go_back(tab->view))
        webkit_web_view_go_back(tab->view);
}

static void on_fwd(GtkButton *_, gpointer __) {
    (void)_; (void)__;
    CyanideTab *tab = tab_current();
    if (tab && webkit_web_view_can_go_forward(tab->view))
        webkit_web_view_go_forward(tab->view);
}

static void on_reload(GtkButton *_, gpointer __) {
    (void)_; (void)__;
    CyanideTab *tab = tab_current();
    if (!tab) return;
    if (tab->is_loading)
        webkit_web_view_stop_loading(tab->view);
    else
        webkit_web_view_reload(tab->view);
}

/* Called when user switches tabs via click or keyboard. */
static void on_switch_page(GtkNotebook *nb, GtkWidget *page,
                            guint page_num, gpointer _) {
    (void)nb; (void)page; (void)_;
    if (!app.tabs || page_num >= app.tabs->len) return;
    CyanideTab *tab = g_ptr_array_index(app.tabs, page_num);
    toolbar_sync(tab);
}

/* ── Per-tab WebKit signal handlers (tab passed as user data) ─────────────── */

static void on_progress_changed(WebKitWebView *v, GParamSpec *_, gpointer data) {
    (void)_;
    CyanideTab *tab = data;
    if (tab != tab_current()) return;
    double p = webkit_web_view_get_estimated_load_progress(v);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app.progress_bar), p);
}

static gboolean on_load_failed(WebKitWebView *v, WebKitLoadEvent ev,
                                const char *failed_uri, GError *err,
                                gpointer data) {
    (void)v; (void)ev; (void)failed_uri; (void)err;
    CyanideTab *tab = data;
    tab->is_loading = FALSE;
    if (tab == tab_current()) toolbar_sync(tab);
    return FALSE;
}

static void on_load_changed(WebKitWebView *v, WebKitLoadEvent ev, gpointer data) {
    CyanideTab *tab = data;
    const char *uri = webkit_web_view_get_uri(v);
    gboolean is_current = (tab == tab_current());

    /* Update tab strip title */
    if (ev == WEBKIT_LOAD_COMMITTED || ev == WEBKIT_LOAD_FINISHED) {
        const char *title = webkit_web_view_get_title(v);
        if (!title || !*title) title = (uri && *uri) ? uri : "New Tab";
        char truncated[TAB_TITLE_MAX + 4];
        if (g_utf8_strlen(title, -1) > TAB_TITLE_MAX) {
            g_utf8_strncpy(truncated, title, TAB_TITLE_MAX);
            strcat(truncated, "\xe2\x80\xa6"); /* … */
        } else {
            g_strlcpy(truncated, title, sizeof(truncated));
        }
        gtk_label_set_text(GTK_LABEL(tab->title_lbl), truncated);
    }

    if (ev == WEBKIT_LOAD_STARTED) {
        tab->is_loading = TRUE;
        if (is_current) {
            gtk_widget_show(app.progress_bar);
            gtk_progress_bar_set_fraction(
                GTK_PROGRESS_BAR(app.progress_bar), 0.05);
            gtk_image_set_from_icon_name(GTK_IMAGE(app.reload_img),
                "process-stop-symbolic", GTK_ICON_SIZE_SMALL_TOOLBAR);
            gtk_widget_set_tooltip_text(app.reload_btn, "Stop loading  (Esc)");
            char *txt = g_strdup("<span foreground='#f9e2af' "
                "font='Inter, Segoe UI, sans-serif 9'>"
                " \xe2\x9a\x97  loading\xe2\x80\xa6</span>");
            gtk_label_set_markup(GTK_LABEL(app.shield_label), txt);
            g_free(txt);
        }
    } else if (ev == WEBKIT_LOAD_FINISHED) {
        tab->is_loading = FALSE;
        if (is_current) {
            gtk_progress_bar_set_fraction(
                GTK_PROGRESS_BAR(app.progress_bar), 1.0);
            gtk_widget_hide(app.progress_bar);
            gtk_image_set_from_icon_name(GTK_IMAGE(app.reload_img),
                "view-refresh-symbolic", GTK_ICON_SIZE_SMALL_TOOLBAR);
            gtk_widget_set_tooltip_text(app.reload_btn, "Reload page  (F5)");
            update_shield();
            if (uri) update_security_icon(uri);
            /* Update URL bar */
            gtk_entry_set_text(GTK_ENTRY(app.url_entry), uri ? uri : "");
        }
    }

    if (ev == WEBKIT_LOAD_COMMITTED && is_current && uri) {
        gtk_entry_set_text(GTK_ENTRY(app.url_entry), uri);
        update_security_icon(uri);
        gtk_widget_set_sensitive(app.back_btn,
            webkit_web_view_can_go_back(v));
        gtk_widget_set_sensitive(app.fwd_btn,
            webkit_web_view_can_go_forward(v));
    }
}

static void on_title_changed(WebKitWebView *v, GParamSpec *_, gpointer data) {
    (void)_;
    CyanideTab *tab = data;
    const char *title = webkit_web_view_get_title(v);

    /* Update tab strip */
    if (!title || !*title) title = "New Tab";
    char truncated[TAB_TITLE_MAX + 4];
    if (g_utf8_strlen(title, -1) > TAB_TITLE_MAX) {
        g_utf8_strncpy(truncated, title, TAB_TITLE_MAX);
        strcat(truncated, "\xe2\x80\xa6");
    } else {
        g_strlcpy(truncated, title, sizeof(truncated));
    }
    gtk_label_set_text(GTK_LABEL(tab->title_lbl), truncated);

    /* Window title only for the active tab */
    if (tab == tab_current()) {
        char *t = g_strdup_printf("Cyanide \xe2\x80\x94 %s", title);
        gtk_window_set_title(GTK_WINDOW(app.window), t);
        g_free(t);
    }
}

static gboolean on_decide_policy(WebKitWebView *v,
                                  WebKitPolicyDecision *dec,
                                  WebKitPolicyDecisionType type,
                                  gpointer data) {
    CyanideTab *tab = data;
    (void)v;

    if (type == WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION ||
        type == WEBKIT_POLICY_DECISION_TYPE_NEW_WINDOW_ACTION) {

        WebKitNavigationPolicyDecision *nav =
            WEBKIT_NAVIGATION_POLICY_DECISION(dec);
        WebKitNavigationAction *action =
            webkit_navigation_policy_decision_get_navigation_action(nav);
        WebKitURIRequest *req =
            webkit_navigation_action_get_request(action);
        const char *uri = webkit_uri_request_get_uri(req);

        if (adblock_should_block(app.adblock, uri)) {
            tab->blocked++;
            g_print("[block] %s\n", uri);
            if (tab == tab_current()) update_shield();
            webkit_policy_decision_ignore(dec);
            return TRUE;
        }

        /* Open target=_blank in a new tab instead of a new window */
        if (type == WEBKIT_POLICY_DECISION_TYPE_NEW_WINDOW_ACTION) {
            tab_new(uri);
            webkit_policy_decision_ignore(dec);
            return TRUE;
        }
    }

    if (type == WEBKIT_POLICY_DECISION_TYPE_RESPONSE) {
        WebKitResponsePolicyDecision *resp =
            WEBKIT_RESPONSE_POLICY_DECISION(dec);
        if (!webkit_response_policy_decision_is_mime_type_supported(resp)) {
            webkit_policy_decision_download(dec);
            return TRUE;
        }
    }

    return FALSE;
}

static void on_mouse_target_changed(WebKitWebView *_, WebKitHitTestResult *hit,
                                    guint _mods, gpointer __) {
    (void)_; (void)_mods; (void)__;
    if (webkit_hit_test_result_context_is_link(hit)) {
        const char *href = webkit_hit_test_result_get_link_uri(hit);
        gtk_statusbar_push(GTK_STATUSBAR(app.status_bar), 0, href ? href : "");
    } else {
        gtk_statusbar_pop(GTK_STATUSBAR(app.status_bar), 0);
    }
}

static gboolean on_key_press(GtkWidget *_, GdkEventKey *ev, gpointer __) {
    (void)_; (void)__;
    guint state = ev->state & gtk_accelerator_get_default_mod_mask();

    /* Ctrl+L — focus URL bar */
    if (state == GDK_CONTROL_MASK && ev->keyval == GDK_KEY_l) {
        gtk_widget_grab_focus(app.url_entry);
        gtk_editable_select_region(GTK_EDITABLE(app.url_entry), 0, -1);
        return TRUE;
    }
    /* Ctrl+T — new tab */
    if (state == GDK_CONTROL_MASK && ev->keyval == GDK_KEY_t) {
        tab_new(NULL);
        return TRUE;
    }
    /* Ctrl+W — close current tab */
    if (state == GDK_CONTROL_MASK && ev->keyval == GDK_KEY_w) {
        tab_close(tab_current());
        return TRUE;
    }
    /* Ctrl+Tab — next tab */
    if (state == GDK_CONTROL_MASK && ev->keyval == GDK_KEY_Tab) {
        int n = gtk_notebook_get_n_pages(GTK_NOTEBOOK(app.notebook));
        int c = gtk_notebook_get_current_page(GTK_NOTEBOOK(app.notebook));
        gtk_notebook_set_current_page(GTK_NOTEBOOK(app.notebook), (c + 1) % n);
        return TRUE;
    }
    /* Ctrl+Shift+Tab — previous tab */
    if (state == (GDK_CONTROL_MASK | GDK_SHIFT_MASK) &&
        ev->keyval == GDK_KEY_Tab) {
        int n = gtk_notebook_get_n_pages(GTK_NOTEBOOK(app.notebook));
        int c = gtk_notebook_get_current_page(GTK_NOTEBOOK(app.notebook));
        gtk_notebook_set_current_page(GTK_NOTEBOOK(app.notebook),
            (c - 1 + n) % n);
        return TRUE;
    }
    /* F5 / Ctrl+R — reload */
    if (ev->keyval == GDK_KEY_F5 ||
        (state == GDK_CONTROL_MASK && ev->keyval == GDK_KEY_r)) {
        CyanideTab *tab = tab_current();
        if (tab) webkit_web_view_reload(tab->view);
        return TRUE;
    }
    /* Alt+Left — back */
    if (state == GDK_MOD1_MASK && ev->keyval == GDK_KEY_Left) {
        CyanideTab *tab = tab_current();
        if (tab && webkit_web_view_can_go_back(tab->view))
            webkit_web_view_go_back(tab->view);
        return TRUE;
    }
    /* Alt+Right — forward */
    if (state == GDK_MOD1_MASK && ev->keyval == GDK_KEY_Right) {
        CyanideTab *tab = tab_current();
        if (tab && webkit_web_view_can_go_forward(tab->view))
            webkit_web_view_go_forward(tab->view);
        return TRUE;
    }
    /* Escape — stop loading */
    if (ev->keyval == GDK_KEY_Escape) {
        CyanideTab *tab = tab_current();
        if (tab) webkit_web_view_stop_loading(tab->view);
        return TRUE;
    }
    return FALSE;
}

/* ── Content-filter (network-level blocking) setup ───────────────────────── */

static void on_filter_saved(GObject *store, GAsyncResult *result, gpointer _) {
    (void)_;
    GError *err = NULL;
    WebKitUserContentFilter *filter =
        webkit_user_content_filter_store_save_finish(
            WEBKIT_USER_CONTENT_FILTER_STORE(store), result, &err);
    if (err) {
        g_printerr("[content-filter] save failed: %s\n", err->message);
        g_error_free(err);
        g_object_unref(store);
        return;
    }
    webkit_user_content_manager_add_filter(app.ucm, filter);
    webkit_user_content_filter_unref(filter);
    g_object_unref(store);
    g_print("[content-filter] Network-level tracker blocking active\n");
}

static void setup_content_filter(void) {
    char *json = adblock_make_filter_json(app.adblock);
    if (!json) return;
    WebKitUserContentFilterStore *store =
        webkit_user_content_filter_store_new(FILTER_STORE_DIR);
    GBytes *bytes = g_bytes_new_take(json, strlen(json));
    webkit_user_content_filter_store_save(
        store, "cyanide-blocklist", bytes, NULL, on_filter_saved, NULL);
    g_bytes_unref(bytes);
}

/* ── Tab create / close ───────────────────────────────────────────────────── */

static void on_tab_close_clicked(GtkButton *btn, gpointer data) {
    (void)btn;
    tab_close((CyanideTab *)data);
}

static void tab_new(const char *url) {
    CyanideTab *tab = g_new0(CyanideTab, 1);
    tab->blocked    = 0;
    tab->is_loading = FALSE;

    /* WebView — shares the app context and UCM */
    tab->view = WEBKIT_WEB_VIEW(
        g_object_new(WEBKIT_TYPE_WEB_VIEW,
            "web-context",          app.ctx,
            "user-content-manager", app.ucm,
            NULL));
    privacy_apply_to_view(&app.privacy, tab->view);

    /* Connect per-tab signals */
    g_signal_connect(tab->view, "load-changed",
        G_CALLBACK(on_load_changed), tab);
    g_signal_connect(tab->view, "load-failed",
        G_CALLBACK(on_load_failed), tab);
    g_signal_connect(tab->view, "notify::estimated-load-progress",
        G_CALLBACK(on_progress_changed), tab);
    g_signal_connect(tab->view, "notify::title",
        G_CALLBACK(on_title_changed), tab);
    g_signal_connect(tab->view, "decide-policy",
        G_CALLBACK(on_decide_policy), tab);
    g_signal_connect(tab->view, "mouse-target-changed",
        G_CALLBACK(on_mouse_target_changed), tab);

    /* ── Tab label widget ── */
    tab->tab_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);

    tab->title_lbl = gtk_label_new("New Tab");
    gtk_label_set_max_width_chars(GTK_LABEL(tab->title_lbl), TAB_TITLE_MAX);
    gtk_label_set_ellipsize(GTK_LABEL(tab->title_lbl), PANGO_ELLIPSIZE_END);
    gtk_widget_set_size_request(tab->title_lbl, 120, -1);
    gtk_box_pack_start(GTK_BOX(tab->tab_box), tab->title_lbl, TRUE, TRUE, 0);

    GtkWidget *close_btn = gtk_button_new();
    gtk_button_set_image(GTK_BUTTON(close_btn),
        gtk_image_new_from_icon_name("window-close-symbolic",
                                      GTK_ICON_SIZE_MENU));
    gtk_button_set_relief(GTK_BUTTON(close_btn), GTK_RELIEF_NONE);
    gtk_widget_set_name(close_btn, "tab-close-btn");
    gtk_widget_set_tooltip_text(close_btn, "Close tab  (Ctrl+W)");
    g_signal_connect(close_btn, "clicked",
        G_CALLBACK(on_tab_close_clicked), tab);
    gtk_box_pack_start(GTK_BOX(tab->tab_box), close_btn, FALSE, FALSE, 0);

    gtk_widget_show_all(tab->tab_box);
    gtk_widget_show(GTK_WIDGET(tab->view));

    /* Add to notebook and tabs array */
    g_ptr_array_add(app.tabs, tab);
    int page_num = gtk_notebook_append_page(
        GTK_NOTEBOOK(app.notebook),
        GTK_WIDGET(tab->view),
        tab->tab_box);
    gtk_notebook_set_tab_reorderable(GTK_NOTEBOOK(app.notebook),
        GTK_WIDGET(tab->view), TRUE);
    gtk_notebook_set_current_page(GTK_NOTEBOOK(app.notebook), page_num);

    /* Navigate */
    if (url && *url) {
        char *full = canonicalize_input(url);
        webkit_web_view_load_uri(tab->view, full);
        g_free(full);
    } else {
        webkit_web_view_load_html(tab->view, START_HTML_PTR, "about:blank");
    }
}

static void tab_close(CyanideTab *tab) {
    if (!tab) return;
    /* If this is the last tab, quit */
    if (app.tabs->len <= 1) {
        gtk_main_quit();
        return;
    }
    /* Find page number */
    int page = -1;
    for (guint i = 0; i < app.tabs->len; i++) {
        if (g_ptr_array_index(app.tabs, i) == tab) {
            page = (int)i;
            break;
        }
    }
    if (page < 0) return;

    g_ptr_array_remove_index(app.tabs, (guint)page);
    gtk_notebook_remove_page(GTK_NOTEBOOK(app.notebook), page);
    /* tab->view is destroyed by GTK when removed from the notebook */
    g_free(tab);
}

/* ── Start page HTML ─────────────────────────────────────────────────────── */
static const char START_HTML[] =
"<!DOCTYPE html>"
"<html lang=\"en\">"
"<head>"
"<meta charset=\"utf-8\">"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
"<title>New Tab \xe2\x80\x94 Cyanide</title>"
"<style>"
":root{"
"  --bg:#1e1e2e;--surface:#181825;--surface2:#313244;"
"  --overlay:#45475a;--text:#cdd6f4;--subtext:#a6adc8;"
"  --muted:#6c7086;--accent:#a6e3a1;"
"}"
"*{margin:0;padding:0;box-sizing:border-box}"
"body{"
"  background:var(--bg);color:var(--text);"
"  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;"
"  min-height:100vh;display:flex;flex-direction:column;"
"  align-items:center;justify-content:center;gap:1.8rem;padding:2rem;"
"}"
".logo{text-align:center;user-select:none}"
".logo-mark{font-size:2.4rem;line-height:1;"
"  filter:drop-shadow(0 0 16px rgba(166,227,161,0.45));}"
".logo-name{font-size:1.9rem;font-weight:800;letter-spacing:.03em;"
"  color:var(--accent);margin-top:.25rem;"
"  text-shadow:0 0 28px rgba(166,227,161,0.22);}"
".logo-tagline{font-size:.7rem;color:var(--muted);"
"  letter-spacing:.22em;text-transform:uppercase;margin-top:.4rem;}"
".search-wrap{width:min(540px,88vw);position:relative}"
".search-input{"
"  width:100%;padding:.75rem 1rem .75rem 2.8rem;"
"  background:var(--surface);border:1.5px solid var(--overlay);"
"  border-radius:12px;color:var(--text);font-size:.95rem;"
"  outline:none;transition:border-color .2s,background .2s;"
"  -webkit-appearance:none;}"
".search-input::placeholder{color:var(--muted)}"
".search-input:focus{border-color:var(--accent);background:var(--surface2)}"
".search-icon{position:absolute;left:1rem;top:50%;transform:translateY(-50%);"
"  font-size:.88rem;pointer-events:none;color:var(--muted);}"
/* recommended sites */
".section-label{"
"  width:min(560px,88vw);font-size:.68rem;color:var(--muted);"
"  text-transform:uppercase;letter-spacing:.18em;margin-bottom:-.5rem;}"
".sites{"
"  display:grid;"
"  grid-template-columns:repeat(auto-fill,minmax(88px,1fr));"
"  gap:.7rem;width:min(560px,88vw);}"
".site{"
"  display:flex;flex-direction:column;align-items:center;gap:.45rem;"
"  background:var(--surface);border:1px solid var(--surface2);"
"  border-radius:12px;padding:.75rem .4rem .6rem;"
"  text-decoration:none;color:var(--subtext);"
"  transition:all .15s;overflow:hidden;}"
".site:hover{"
"  background:var(--surface2);border-color:var(--overlay);"
"  color:var(--text);transform:translateY(-2px);"
"  box-shadow:0 4px 14px rgba(0,0,0,.35);}"
".site-icon{"
"  width:36px;height:36px;border-radius:8px;"
"  object-fit:contain;display:block;flex-shrink:0;"
"  background:var(--surface2);}"
".site-name{font-size:.7rem;text-align:center;line-height:1.2;"
"  max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}"
".footer{display:flex;align-items:center;gap:.7rem;"
"  font-size:.65rem;color:var(--muted);flex-wrap:wrap;justify-content:center;}"
".sep{width:3px;height:3px;border-radius:50%;background:var(--overlay)}"
".ver{color:var(--accent);font-weight:700}"
"</style>"
"</head>"
"<body>"
"<div class=\"logo\">"
"  <div class=\"logo-mark\">\xe2\x9a\x97</div>"
"  <div class=\"logo-name\">Cyanide Browser</div>"
"  <div class=\"logo-tagline\">Privacy &middot; Data Poisoning &middot; Protection</div>"
"</div>"
"<div class=\"search-wrap\">"
"  <span class=\"search-icon\">\xf0\x9f\x94\x8d</span>"
"  <input class=\"search-input\" type=\"text\" autofocus"
"         placeholder=\"Search DuckDuckGo or enter a URL\xe2\x80\xa6\""
"         onkeydown=\"if(event.key==='Enter'){var v=this.value.trim();"
"           if(v){if(v.startsWith('http')||v.startsWith('about:'))window.location=v;"
"           else if(v.indexOf('.')>-1&&v.indexOf(' ')<0)window.location='https://'+v;"
"           else window.location='https://duckduckgo.com/?q='+encodeURIComponent(v);}}\"/>"
"</div>"
"<p class=\"section-label\">Recommended</p>"
"<div class=\"sites\">"
"  <a class=\"site\" href=\"https://duckduckgo.com\">"
"    <img class=\"site-icon\""
"         src=\"https://icons.duckduckgo.com/ip3/duckduckgo.com.ico\""
"         alt=\"\" width=\"36\" height=\"36\">"
"    <span class=\"site-name\">DuckDuckGo</span>"
"  </a>"
"  <a class=\"site\" href=\"https://en.wikipedia.org\">"
"    <img class=\"site-icon\""
"         src=\"https://icons.duckduckgo.com/ip3/wikipedia.org.ico\""
"         alt=\"\" width=\"36\" height=\"36\">"
"    <span class=\"site-name\">Wikipedia</span>"
"  </a>"
"  <a class=\"site\" href=\"https://github.com\">"
"    <img class=\"site-icon\""
"         src=\"https://icons.duckduckgo.com/ip3/github.com.ico\""
"         alt=\"\" width=\"36\" height=\"36\">"
"    <span class=\"site-name\">GitHub</span>"
"  </a>"
"  <a class=\"site\" href=\"https://www.youtube.com\">"
"    <img class=\"site-icon\""
"         src=\"https://icons.duckduckgo.com/ip3/youtube.com.ico\""
"         alt=\"\" width=\"36\" height=\"36\">"
"    <span class=\"site-name\">YouTube</span>"
"  </a>"
"  <a class=\"site\" href=\"https://www.openstreetmap.org\">"
"    <img class=\"site-icon\""
"         src=\"https://icons.duckduckgo.com/ip3/openstreetmap.org.ico\""
"         alt=\"\" width=\"36\" height=\"36\">"
"    <span class=\"site-name\">OSM Maps</span>"
"  </a>"
"  <a class=\"site\" href=\"https://proton.me/mail\">"
"    <img class=\"site-icon\""
"         src=\"https://icons.duckduckgo.com/ip3/proton.me.ico\""
"         alt=\"\" width=\"36\" height=\"36\">"
"    <span class=\"site-name\">ProtonMail</span>"
"  </a>"
"  <a class=\"site\" href=\"https://news.ycombinator.com\">"
"    <img class=\"site-icon\""
"         src=\"https://icons.duckduckgo.com/ip3/ycombinator.com.ico\""
"         alt=\"\" width=\"36\" height=\"36\">"
"    <span class=\"site-name\">Hacker News</span>"
"  </a>"
"  <a class=\"site\" href=\"https://www.reddit.com\">"
"    <img class=\"site-icon\""
"         src=\"https://icons.duckduckgo.com/ip3/reddit.com.ico\""
"         alt=\"\" width=\"36\" height=\"36\">"
"    <span class=\"site-name\">Reddit</span>"
"  </a>"
"  <a class=\"site\" href=\"https://wiki.archlinux.org\">"
"    <img class=\"site-icon\""
"         src=\"https://icons.duckduckgo.com/ip3/archlinux.org.ico\""
"         alt=\"\" width=\"36\" height=\"36\">"
"    <span class=\"site-name\">Arch Wiki</span>"
"  </a>"
"  <a class=\"site\" href=\"https://stackoverflow.com\">"
"    <img class=\"site-icon\""
"         src=\"https://icons.duckduckgo.com/ip3/stackoverflow.com.ico\""
"         alt=\"\" width=\"36\" height=\"36\">"
"    <span class=\"site-name\">Stack Overflow</span>"
"  </a>"
"  <a class=\"site\" href=\"https://www.wolframalpha.com\">"
"    <img class=\"site-icon\""
"         src=\"https://icons.duckduckgo.com/ip3/wolframalpha.com.ico\""
"         alt=\"\" width=\"36\" height=\"36\">"
"    <span class=\"site-name\">Wolfram Alpha</span>"
"  </a>"
"  <a class=\"site\" href=\"https://web.archive.org\">"
"    <img class=\"site-icon\""
"         src=\"https://icons.duckduckgo.com/ip3/archive.org.ico\""
"         alt=\"\" width=\"36\" height=\"36\">"
"    <span class=\"site-name\">Wayback Machine</span>"
"  </a>"
"</div>"
"<div class=\"footer\">"
"  <span>No history</span><div class=\"sep\"></div>"
"  <span>No cache</span><div class=\"sep\"></div>"
"  <span>No persistent data</span><div class=\"sep\"></div>"
"  <span class=\"ver\">Cyanide v" CYANIDE_VERSION "</span>"
"</div>"
"</body></html>";

/* ── UI construction ─────────────────────────────────────────────────────── */

static void apply_css(void) {
    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css,
        /* ── Base ── */
        "window { background-color: #1e1e2e; }"

        /* ── Toolbar ── */
        "#toolbar {"
        "  background-color: #181825;"
        "  border-bottom: 1px solid #313244;"
        "  padding: 5px 6px;"
        "}"

        /* ── Nav buttons ── */
        "#toolbar button {"
        "  background-color: transparent;"
        "  border: 1px solid transparent;"
        "  border-radius: 6px;"
        "  color: #9399b2;"
        "  min-width: 30px;"
        "  min-height: 30px;"
        "  padding: 4px 6px;"
        "}"
        "#toolbar button:hover {"
        "  background-color: #313244;"
        "  border-color: #45475a;"
        "  color: #a6e3a1;"
        "}"
        "#toolbar button:active { background-color: #45475a; }"
        "#toolbar button:disabled { opacity: 0.3; }"
        "#toolbar separator {"
        "  background-color: #313244;"
        "  min-width: 1px;"
        "  margin: 5px 2px;"
        "}"

        /* ── URL entry ── */
        "#url-entry {"
        "  background-color: #313244;"
        "  color: #cdd6f4;"
        "  caret-color: #a6e3a1;"
        "  border: 1.5px solid #45475a;"
        "  border-radius: 8px;"
        "  padding: 5px 12px;"
        "  font-size: 13px;"
        "  min-height: 34px;"
        "}"
        "#url-entry:focus {"
        "  border-color: #a6e3a1;"
        "  background-color: #383b52;"
        "}"

        /* ── Shield badge ── */
        "#shield-badge {"
        "  background-color: #1e2d27;"
        "  border: 1px solid #2e4d38;"
        "  border-radius: 14px;"
        "  padding: 3px 10px;"
        "  font-size: 10px;"
        "  color: #a6e3a1;"
        "}"

        /* ── Loading progress bar ── */
        "progressbar#load-progress { min-height: 3px; }"
        "progressbar#load-progress trough {"
        "  background-color: #181825;"
        "  min-height: 3px;"
        "  border-radius: 0;"
        "  border: none;"
        "}"
        "progressbar#load-progress trough progress {"
        "  background-color: #a6e3a1;"
        "  min-height: 3px;"
        "  border-radius: 0;"
        "}"

        /* ── Status bar ── */
        "statusbar#main-statusbar {"
        "  background-color: #181825;"
        "  border-top: 1px solid #313244;"
        "  min-height: 20px;"
        "  padding: 0 8px;"
        "}"
        "statusbar#main-statusbar label {"
        "  color: #6c7086;"
        "  font-size: 11px;"
        "}"

        /* ── Notebook / tab strip ── */
        "notebook#tab-notebook {"
        "  background-color: #1e1e2e;"
        "}"
        "notebook#tab-notebook header {"
        "  background-color: #181825;"
        "  border-bottom: 1px solid #313244;"
        "  padding: 0 2px;"
        "}"
        "notebook#tab-notebook header tab {"
        "  background-color: transparent;"
        "  border: 1px solid transparent;"
        "  border-radius: 6px 6px 0 0;"
        "  padding: 5px 6px 5px 10px;"
        "  color: #6c7086;"
        "  font-size: 12px;"
        "  min-width: 80px;"
        "}"
        "notebook#tab-notebook header tab:hover {"
        "  background-color: #313244;"
        "  color: #cdd6f4;"
        "}"
        "notebook#tab-notebook header tab:checked {"
        "  background-color: #1e1e2e;"
        "  border-color: #313244;"
        "  border-bottom-color: transparent;"
        "  color: #cdd6f4;"
        "}"

        /* ── Tab close button ── */
        "button#tab-close-btn {"
        "  background-color: transparent;"
        "  border: none;"
        "  border-radius: 4px;"
        "  padding: 1px;"
        "  min-width: 16px;"
        "  min-height: 16px;"
        "  color: #6c7086;"
        "}"
        "button#tab-close-btn:hover {"
        "  background-color: #f38ba8;"
        "  color: #1e1e2e;"
        "}"

        /* ── New-tab button ── */
        "button#new-tab-btn {"
        "  background-color: transparent;"
        "  border: 1px solid transparent;"
        "  border-radius: 6px;"
        "  color: #6c7086;"
        "  padding: 4px 6px;"
        "}"
        "button#new-tab-btn:hover {"
        "  background-color: #313244;"
        "  color: #a6e3a1;"
        "}"

        /* ── Settings popover ── */
        "#settings-popover .popover-contents {"
        "  background-color: #181825;"
        "}"
        "popover#settings-popover > contents {"
        "  background-color: #181825;"
        "  border: 1px solid #313244;"
        "  border-radius: 10px;"
        "  padding: 2px;"
        "}"
        "box#menu-box { background-color: #181825; }"
        "button#menu-row-btn {"
        "  background-color: transparent;"
        "  border: none;"
        "  border-radius: 6px;"
        "  padding: 6px 8px;"
        "  min-width: 200px;"
        "}"
        "button#menu-row-btn:hover { background-color: #313244; }"
        "label#menu-row-label { color: #cdd6f4; font-size: 13px; }"
        "button#zoom-btn {"
        "  background-color: #313244;"
        "  border: 1px solid #45475a;"
        "  border-radius: 6px;"
        "  color: #cdd6f4;"
        "  padding: 3px 10px;"
        "  min-width: 32px;"
        "}"
        "button#zoom-btn:hover { background-color: #45475a; color: #a6e3a1; }"
        "box#zoom-row { padding: 4px 8px; }"
        "button#menu-btn {"
        "  background-color: transparent;"
        "  border: 1px solid transparent;"
        "  border-radius: 6px;"
        "  color: #9399b2;"
        "  min-width: 30px; min-height: 30px; padding: 4px 6px;"
        "}"
        "button#menu-btn:hover {"
        "  background-color: #313244;"
        "  border-color: #45475a;"
        "  color: #a6e3a1;"
        "}",
        -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);
}


/* ── Settings popover ────────────────────────────────────────────────────── */

static void on_menu_clicked(GtkButton *_, gpointer __) {
    (void)_; (void)__;
    gtk_popover_popup(GTK_POPOVER(app.menu_popover));
}

static void on_new_tab_menu(GtkButton *_, gpointer __) {
    (void)_; (void)__;
    gtk_popover_popdown(GTK_POPOVER(app.menu_popover));
    tab_new(NULL);
}

static void on_zoom_in(GtkButton *_, gpointer __) {
    (void)_; (void)__;
    CyanideTab *tab = tab_current();
    if (!tab) return;
    double z = webkit_web_view_get_zoom_level(tab->view);
    webkit_web_view_set_zoom_level(tab->view, z + 0.1);
}

static void on_zoom_out(GtkButton *_, gpointer __) {
    (void)_; (void)__;
    CyanideTab *tab = tab_current();
    if (!tab) return;
    double z = webkit_web_view_get_zoom_level(tab->view);
    webkit_web_view_set_zoom_level(tab->view, z - 0.1);
}

static void on_zoom_reset(GtkButton *_, gpointer __) {
    (void)_; (void)__;
    CyanideTab *tab = tab_current();
    if (tab) webkit_web_view_set_zoom_level(tab->view, 1.0);
}

static void on_find_toggled(GtkButton *_, gpointer __) {
    (void)_; (void)__;
    gtk_popover_popdown(GTK_POPOVER(app.menu_popover));
    CyanideTab *tab = tab_current();
    if (!tab) return;
    WebKitFindController *fc = webkit_web_view_get_find_controller(tab->view);
    webkit_find_controller_search(fc, "", WEBKIT_FIND_OPTIONS_CASE_INSENSITIVE, G_MAXUINT);
}

static void on_print_page(GtkButton *_, gpointer __) {
    (void)_; (void)__;
    gtk_popover_popdown(GTK_POPOVER(app.menu_popover));
    CyanideTab *tab = tab_current();
    if (!tab) return;
    WebKitPrintOperation *op = webkit_print_operation_new(tab->view);
    webkit_print_operation_run_dialog(op, GTK_WINDOW(app.window));
    g_object_unref(op);
}

static void on_view_source(GtkButton *_, gpointer __) {
    (void)_; (void)__;
    gtk_popover_popdown(GTK_POPOVER(app.menu_popover));
    CyanideTab *tab = tab_current();
    if (!tab) return;
    const char *uri = webkit_web_view_get_uri(tab->view);
    if (!uri || !*uri) return;
    char *src_uri = g_strdup_printf("view-source:%s", uri);
    tab_new(src_uri);
    g_free(src_uri);
}

static void on_clear_data(GtkButton *_, gpointer __) {
    (void)_; (void)__;
    gtk_popover_popdown(GTK_POPOVER(app.menu_popover));
    /* Ephemeral context has no persistent storage; just reload all tabs */
    for (guint i = 0; i < app.tabs->len; i++) {
        CyanideTab *t = g_ptr_array_index(app.tabs, i);
        webkit_web_view_reload(t->view);
    }
    g_print("[settings] Session cleared (all tabs reloaded)\n");
}

static GtkWidget *menu_row(const char *icon_name, const char *label,
                            GCallback cb) {
    GtkWidget *btn = gtk_button_new();
    gtk_button_set_relief(GTK_BUTTON(btn), GTK_RELIEF_NONE);
    gtk_widget_set_name(btn, "menu-row-btn");

    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_halign(hbox, GTK_ALIGN_START);

    GtkWidget *ico = gtk_image_new_from_icon_name(icon_name,
                                                   GTK_ICON_SIZE_MENU);
    gtk_box_pack_start(GTK_BOX(hbox), ico, FALSE, FALSE, 0);

    GtkWidget *lbl = gtk_label_new(label);
    gtk_widget_set_name(lbl, "menu-row-label");
    gtk_box_pack_start(GTK_BOX(hbox), lbl, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(btn), hbox);
    if (cb) g_signal_connect(btn, "clicked", cb, NULL);
    return btn;
}

static GtkWidget *zoom_row(void) {
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_widget_set_name(hbox, "zoom-row");

    GtkWidget *lbl = gtk_label_new("Zoom");
    gtk_widget_set_name(lbl, "menu-row-label");
    gtk_widget_set_hexpand(lbl, TRUE);
    gtk_widget_set_halign(lbl, GTK_ALIGN_START);

    GtkWidget *out_btn = gtk_button_new_with_label("â");
    GtkWidget *reset_btn = gtk_button_new_with_label("100%");
    GtkWidget *in_btn  = gtk_button_new_with_label("+");
    gtk_widget_set_name(out_btn,   "zoom-btn");
    gtk_widget_set_name(reset_btn, "zoom-btn");
    gtk_widget_set_name(in_btn,    "zoom-btn");
    gtk_widget_set_tooltip_text(out_btn,   "Zoom out");
    gtk_widget_set_tooltip_text(reset_btn, "Reset zoom");
    gtk_widget_set_tooltip_text(in_btn,    "Zoom in");

    g_signal_connect(out_btn,   "clicked", G_CALLBACK(on_zoom_out),   NULL);
    g_signal_connect(reset_btn, "clicked", G_CALLBACK(on_zoom_reset), NULL);
    g_signal_connect(in_btn,    "clicked", G_CALLBACK(on_zoom_in),    NULL);

    gtk_box_pack_start(GTK_BOX(hbox), lbl,       TRUE,  TRUE,  8);
    gtk_box_pack_start(GTK_BOX(hbox), out_btn,   FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), reset_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), in_btn,    FALSE, FALSE, 0);
    return hbox;
}

static void build_settings_popover(GtkWidget *relative_to) {
    app.menu_popover = gtk_popover_new(relative_to);
    gtk_widget_set_name(app.menu_popover, "settings-popover");
    gtk_popover_set_position(GTK_POPOVER(app.menu_popover), GTK_POS_BOTTOM);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_set_name(vbox, "menu-box");
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 6);

    /* ── Navigation ── */
    gtk_box_pack_start(GTK_BOX(vbox),
        menu_row("tab-new-symbolic",        "New Tab",
                 G_CALLBACK(on_new_tab_menu)), FALSE, FALSE, 0);

    GtkWidget *sep1 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(vbox), sep1, FALSE, FALSE, 4);

    /* ── Zoom ── */
    gtk_box_pack_start(GTK_BOX(vbox), zoom_row(), FALSE, FALSE, 0);

    GtkWidget *sep2 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(vbox), sep2, FALSE, FALSE, 4);

    /* ── Page tools ── */
    gtk_box_pack_start(GTK_BOX(vbox),
        menu_row("edit-find-symbolic",      "Find in Page",
                 G_CALLBACK(on_find_toggled)), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox),
        menu_row("printer-symbolic",        "Printâ¦",
                 G_CALLBACK(on_print_page)), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox),
        menu_row("text-x-generic-symbolic", "View Page Source",
                 G_CALLBACK(on_view_source)), FALSE, FALSE, 0);

    GtkWidget *sep3 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(vbox), sep3, FALSE, FALSE, 4);

    /* ── Privacy ── */
    gtk_box_pack_start(GTK_BOX(vbox),
        menu_row("edit-clear-all-symbolic", "Clear Session Data",
                 G_CALLBACK(on_clear_data)), FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(app.menu_popover), vbox);
    gtk_widget_show_all(vbox);
}

static void build_ui(void) {
    /* ── Window ── */
    app.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app.window), "Cyanide Browser");
    gtk_window_set_default_size(GTK_WINDOW(app.window), WINDOW_W, WINDOW_H);
    g_signal_connect(app.window, "destroy",         G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect(app.window, "key-press-event", G_CALLBACK(on_key_press),  NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(app.window), vbox);

    /* ── Toolbar ── */
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
    gtk_widget_set_name(toolbar, "toolbar");
    gtk_container_set_border_width(GTK_CONTAINER(toolbar), 0);
    gtk_box_pack_start(GTK_BOX(vbox), toolbar, FALSE, FALSE, 0);

    app.back_btn = gtk_button_new();
    gtk_button_set_image(GTK_BUTTON(app.back_btn),
        gtk_image_new_from_icon_name("go-previous-symbolic",
                                      GTK_ICON_SIZE_SMALL_TOOLBAR));
    gtk_button_set_relief(GTK_BUTTON(app.back_btn), GTK_RELIEF_NONE);
    gtk_widget_set_tooltip_text(app.back_btn, "Go back  (Alt+Left)");
    gtk_widget_set_sensitive(app.back_btn, FALSE);
    g_signal_connect(app.back_btn, "clicked", G_CALLBACK(on_back), NULL);

    app.fwd_btn = gtk_button_new();
    gtk_button_set_image(GTK_BUTTON(app.fwd_btn),
        gtk_image_new_from_icon_name("go-next-symbolic",
                                      GTK_ICON_SIZE_SMALL_TOOLBAR));
    gtk_button_set_relief(GTK_BUTTON(app.fwd_btn), GTK_RELIEF_NONE);
    gtk_widget_set_tooltip_text(app.fwd_btn, "Go forward  (Alt+Right)");
    gtk_widget_set_sensitive(app.fwd_btn, FALSE);
    g_signal_connect(app.fwd_btn, "clicked", G_CALLBACK(on_fwd), NULL);

    app.reload_img = gtk_image_new_from_icon_name("view-refresh-symbolic",
                                                   GTK_ICON_SIZE_SMALL_TOOLBAR);
    app.reload_btn = gtk_button_new();
    gtk_button_set_image(GTK_BUTTON(app.reload_btn), app.reload_img);
    gtk_button_set_relief(GTK_BUTTON(app.reload_btn), GTK_RELIEF_NONE);
    gtk_widget_set_tooltip_text(app.reload_btn, "Reload page  (F5)");
    g_signal_connect(app.reload_btn, "clicked", G_CALLBACK(on_reload), NULL);

    gtk_box_pack_start(GTK_BOX(toolbar), app.back_btn,   FALSE, FALSE, 4);
    gtk_box_pack_start(GTK_BOX(toolbar), app.fwd_btn,    FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(toolbar), app.reload_btn, FALSE, FALSE, 0);

    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_VERTICAL);
    gtk_box_pack_start(GTK_BOX(toolbar), sep, FALSE, FALSE, 6);

    app.url_entry = gtk_entry_new();
    gtk_widget_set_name(app.url_entry, "url-entry");
    gtk_entry_set_placeholder_text(GTK_ENTRY(app.url_entry),
        "Search DuckDuckGo or enter a URL\xe2\x80\xa6");
    gtk_entry_set_icon_from_icon_name(
        GTK_ENTRY(app.url_entry), GTK_ENTRY_ICON_PRIMARY,
        "dialog-question-symbolic");
    g_signal_connect(app.url_entry, "activate",
        G_CALLBACK(on_url_activate), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), app.url_entry, TRUE, TRUE, 4);

    app.shield_label = gtk_label_new(NULL);
    gtk_widget_set_name(app.shield_label, "shield-badge");
    gtk_box_pack_start(GTK_BOX(toolbar), app.shield_label, FALSE, FALSE, 8);
    update_shield();

    /* ── Settings / menu button ── */
    app.menu_btn = gtk_button_new();
    gtk_button_set_image(GTK_BUTTON(app.menu_btn),
        gtk_image_new_from_icon_name("open-menu-symbolic",
                                      GTK_ICON_SIZE_SMALL_TOOLBAR));
    gtk_button_set_relief(GTK_BUTTON(app.menu_btn), GTK_RELIEF_NONE);
    gtk_widget_set_name(app.menu_btn, "menu-btn");
    gtk_widget_set_tooltip_text(app.menu_btn, "Menu");
    g_signal_connect(app.menu_btn, "clicked",
        G_CALLBACK(on_menu_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), app.menu_btn, FALSE, FALSE, 4);
    build_settings_popover(app.menu_btn);

    /* ── Progress bar ── */
    app.progress_bar = gtk_progress_bar_new();
    gtk_widget_set_name(app.progress_bar, "load-progress");
    gtk_box_pack_start(GTK_BOX(vbox), app.progress_bar, FALSE, FALSE, 0);
    gtk_widget_set_no_show_all(app.progress_bar, TRUE);

    /* ── Notebook (tab strip) ── */
    app.notebook = gtk_notebook_new();
    gtk_widget_set_name(app.notebook, "tab-notebook");
    gtk_notebook_set_scrollable(GTK_NOTEBOOK(app.notebook), TRUE);
    gtk_notebook_set_show_border(GTK_NOTEBOOK(app.notebook), FALSE);
    g_signal_connect(app.notebook, "switch-page",
        G_CALLBACK(on_switch_page), NULL);

    /* "New tab" button in the notebook action area */
    GtkWidget *new_tab_btn = gtk_button_new();
    gtk_button_set_image(GTK_BUTTON(new_tab_btn),
        gtk_image_new_from_icon_name("tab-new-symbolic",
                                      GTK_ICON_SIZE_SMALL_TOOLBAR));
    gtk_button_set_relief(GTK_BUTTON(new_tab_btn), GTK_RELIEF_NONE);
    gtk_widget_set_name(new_tab_btn, "new-tab-btn");
    gtk_widget_set_tooltip_text(new_tab_btn, "New tab  (Ctrl+T)");
    g_signal_connect_swapped(new_tab_btn, "clicked",
        G_CALLBACK(tab_new), NULL);
    gtk_widget_show(new_tab_btn);
    gtk_notebook_set_action_widget(GTK_NOTEBOOK(app.notebook),
        new_tab_btn, GTK_PACK_END);

    gtk_box_pack_start(GTK_BOX(vbox), app.notebook, TRUE, TRUE, 0);

    /* ── Status bar ── */
    app.status_bar = gtk_statusbar_new();
    gtk_widget_set_name(app.status_bar, "main-statusbar");
    gtk_box_pack_start(GTK_BOX(vbox), app.status_bar, FALSE, FALSE, 0);

    gtk_widget_show_all(app.window);
}

/* ══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);
    srand((unsigned)time(NULL));

    g_print("Cyanide Browser v%s \xe2\x80\x94 Privacy/Data-Poisoning Edition\n",
            CYANIDE_VERSION);

    app.tabs       = g_ptr_array_new();
    START_HTML_PTR = START_HTML;

    /* Privacy */
    privacy_init(&app.privacy, PRIVACY_LEVEL_HIGH);

    /* Tracker blocker */
    app.adblock = adblock_new();
    adblock_load_file(app.adblock, "data/blocklist.txt");

    /* Shared ephemeral context */
    app.ctx = webkit_web_context_new_ephemeral();
    privacy_apply_to_context(&app.privacy, app.ctx);

    /* Shared UCM — poison scripts registered once, applied to every tab */
    app.ucm = webkit_user_content_manager_new();
    privacy_inject_scripts(&app.privacy, app.ucm);

    /* Build chrome (window + toolbar, no view yet) */
    apply_css();
    build_ui();

    /* Network-level content filter (async) */
    setup_content_filter();

    /* Open first tab */
    tab_new(argc > 1 ? argv[1] : NULL);

    gtk_main();

    adblock_free(app.adblock);
    g_ptr_array_free(app.tabs, FALSE);
    return 0;
}impo
