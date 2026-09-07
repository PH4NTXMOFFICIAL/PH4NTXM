user_pref("general.useragent.override", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{{FIREFOX_MAJOR}}.0) Gecko/20100101 Firefox/{{FIREFOX_MAJOR}}.0");

user_pref("browser.startup.page", 0);
user_pref("browser.startup.homepage", "about:blank");
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.newtabpage.enabled", false);

user_pref("layout.css.devPixelsPerPx", "{{DPR}}");
user_pref("dom.maxHardwareConcurrency", {{CORES}});

user_pref("general.oscpu.override", "Windows NT 10.0; Win64; x64");
user_pref("general.platform.override", "Win32");

user_pref("browser.search.region", "US");
user_pref("browser.search.isUS", true);
user_pref("intl.accept_languages", "en-US, en");

user_pref("browser.region.update.enabled", false);
user_pref("browser.region.network.url", "");
user_pref("browser.region.update.region", "US");

user_pref("browser.search.geoip.url", "");
user_pref("browser.search.geoSpecificDefaults", false);
user_pref("browser.search.geoSpecificDefaults.url", "");

user_pref("doh-rollout.home-region", "US");
user_pref("doh-rollout.disable-heuristics", true);

user_pref("network.cookie.cookieBehavior", 5);

user_pref("permissions.default.geo", 2);

user_pref("privacy.trackingprotection.enabled", true);

user_pref("media.peerconnection.enabled", false);

user_pref("privacy.cpd.canvas", true);

user_pref("dom.webaudio.enabled", false);

user_pref("webgl.disabled", true);

user_pref("pdfjs.enableWebGL", false);

user_pref("gfx.font_rendering.opentype_svg.enabled", false);

user_pref("network.proxy.no_proxies_on", "");

user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.block_dangerous", false);
user_pref("browser.safebrowsing.downloads.remote.block_dangerous_host", false);

user_pref("browser.send_pings", false);

user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);

user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);

user_pref("network.prefetch-next", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.predictor.enabled", false);
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_pbm", true);
user_pref("network.trr.mode", 5);

user_pref("beacon.enabled", false);

user_pref("canvas.capturestream.enabled", false);
user_pref("canvas.focusring.enabled", false);

user_pref("dom.textMetrics.enabled", false);

user_pref("browser.cache.disk.enable", false);
user_pref("browser.formfill.enable", false);
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
