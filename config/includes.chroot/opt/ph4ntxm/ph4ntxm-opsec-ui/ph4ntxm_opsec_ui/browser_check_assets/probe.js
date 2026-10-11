"use strict";

(() => {
    const element = (id) => document.getElementById(id);
    const statusLabels = {
        match: "MATCHES",
        different: "DIFFERS",
        blocked: "BLOCKED",
        unavailable: "UNAVAILABLE",
        info: "INFO"
    };

    function readValue(read) {
        try {
            const value = read();
            return value === undefined ? null : value;
        } catch {
            return null;
        }
    }

    function webglAvailable() {
        const canvas = document.createElement("canvas");
        const context = canvas.getContext("webgl2") || canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
        if (!context) {
            return false;
        }
        const release = context.getExtension("WEBGL_lose_context");
        if (release) {
            release.loseContext();
        }
        return true;
    }

    async function fontCandidates(signal) {
        try {
            const response = await fetch(new URL("config", window.location.href), {
                credentials: "omit",
                cache: "no-store",
                redirect: "error",
                signal
            });
            if (!response.ok) {
                return null;
            }
            const config = await response.json();
            const families = config.font_families;
            if (!Array.isArray(families) || families.length > 24 || !families.every((family) => typeof family === "string" && family.length > 0 && family.length <= 128)) {
                return null;
            }
            return families;
        } catch {
            return null;
        }
    }

    function observedFonts(families) {
        if (!families || families.length === 0) {
            return null;
        }
        const sample = document.createElement("span");
        sample.className = "font-probe-sample";
        sample.setAttribute("aria-hidden", "true");
        sample.textContent = "mmmmmmmmmmlliWW0123456789";
        let rule;
        let originalFamily;
        try {
            for (const sheet of document.styleSheets) {
                rule = Array.from(sheet.cssRules).find((item) => item.selectorText === ".font-probe-sample");
                if (rule) {
                    break;
                }
            }
            if (!rule) {
                return null;
            }
            originalFamily = rule.style.fontFamily;
            document.body.appendChild(sample);
            const measure = (family) => {
                rule.style.fontFamily = family;
                const { width, height } = sample.getBoundingClientRect();
                if (!Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0) {
                    throw new Error("Font metrics are unavailable.");
                }
                return { width, height };
            };
            const differs = (first, second) => Math.abs(first.width - second.width) > 0.01 || Math.abs(first.height - second.height) > 0.01;
            const baselines = ["monospace", "sans-serif", "serif"].map((family) => ({ family, metrics: measure(family) }));
            for (const baseline of baselines) {
                const missing = measure('"__PH4NTXM_MISSING_FONT_0d9f7c1a__", ' + baseline.family);
                if (differs(missing, baseline.metrics)) {
                    return null;
                }
            }
            return families.filter((family) => baselines.some((baseline) => differs(measure(CSS.escape(family) + ", " + baseline.family), baseline.metrics)));
        } catch {
            return null;
        } finally {
            sample.remove();
            if (rule && originalFamily !== undefined) {
                rule.style.fontFamily = originalFamily;
            }
        }
    }

    function collect(families) {
        return {
            schema_version: 1,
            navigator: {
                userAgent: readValue(() => navigator.userAgent),
                platform: readValue(() => navigator.platform),
                oscpu: readValue(() => navigator.oscpu),
                appVersion: readValue(() => navigator.appVersion),
                hardwareConcurrency: readValue(() => navigator.hardwareConcurrency),
                languages: readValue(() => Array.from(navigator.languages))
            },
            timezone: readValue(() => Intl.DateTimeFormat().resolvedOptions().timeZone),
            screen: {
                width: readValue(() => screen.width),
                height: readValue(() => screen.height),
                availWidth: readValue(() => screen.availWidth),
                availHeight: readValue(() => screen.availHeight),
                devicePixelRatio: readValue(() => window.devicePixelRatio),
                innerWidth: readValue(() => window.innerWidth),
                innerHeight: readValue(() => window.innerHeight)
            },
            features: {
                webgl: readValue(webglAvailable),
                webrtc: readValue(() => typeof window.RTCPeerConnection === "function" || typeof window.webkitRTCPeerConnection === "function"),
                webaudio: readValue(() => typeof window.AudioContext === "function" || typeof window.webkitAudioContext === "function")
            },
            fonts: observedFonts(families)
        };
    }

    function formatValue(value) {
        if (value === null || value === undefined || value === "") {
            return "Unavailable";
        }
        if (Array.isArray(value)) {
            return value.length ? value.map(formatValue).join(", ") : "None detected";
        }
        if (typeof value === "boolean") {
            return value ? "Available" : "Unavailable / blocked";
        }
        return String(value);
    }

    function addCell(row, label, value, className) {
        const cell = document.createElement("td");
        cell.dataset.label = label;
        cell.className = className;
        cell.textContent = formatValue(value);
        row.appendChild(cell);
        return cell;
    }

    function renderResult(result) {
        const rows = document.createDocumentFragment();
        for (const item of result.rows) {
            const row = document.createElement("tr");
            const name = document.createElement("th");
            name.scope = "row";
            name.className = "check-name";
            name.textContent = formatValue(item.label);
            if (item.detail) {
                const detail = document.createElement("span");
                detail.className = "check-detail";
                detail.textContent = String(item.detail);
                name.appendChild(detail);
            }
            row.appendChild(name);
            addCell(row, "Expected", item.expected, "value expected-value");
            addCell(row, "Observed", item.observed, "value observed-value");
            const status = Object.hasOwn(statusLabels, item.status) ? item.status : "info";
            const cell = addCell(row, "Result", "", "result-cell");
            const badge = document.createElement("span");
            badge.className = "badge badge-" + status;
            badge.textContent = statusLabels[status];
            cell.replaceChildren(badge);
            rows.appendChild(row);
        }
        element("result-rows").replaceChildren(rows);
        element("mode").textContent = "Active mode · " + formatValue(result.mode);
        const collectedAt = new Date(result.collected_at);
        element("collected-at").textContent = Number.isNaN(collectedAt.getTime()) ? "Report received" : "Checked " + collectedAt.toLocaleString();
        if (result.edition === "ghost" || result.edition === "abyss") {
            document.documentElement.dataset.edition = result.edition;
        }
        const differences = result.rows.filter((row) => row.status === "different").length;
        const unavailable = result.rows.filter((row) => row.status === "unavailable").length;
        element("result-count").textContent = result.rows.length + " checks";
        element("check-status").textContent = differences ? "Review the differences" : "Check complete";
        element("status-icon").textContent = differences || unavailable ? "!" : "✓";
        element("status-icon").className = "status-icon " + (differences ? "status-different" : unavailable ? "status-unavailable" : "status-complete");
        element("check-detail").textContent = differences + " different · " + unavailable + " unavailable. Review each result in context below.";
        element("results").hidden = false;
        element("results-link").hidden = false;
    }

    async function run() {
        element("check-status").textContent = "Checking this browser…";
        element("check-detail").textContent = "Reading browser values and comparing them with the active mode.";
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 15000);
        try {
            const families = await fontCandidates(controller.signal);
            const response = await fetch(new URL("result", window.location.href), {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                credentials: "omit",
                cache: "no-store",
                redirect: "error",
                signal: controller.signal,
                body: JSON.stringify(collect(families))
            });
            if (!response.ok) {
                throw new Error("The local checker did not accept this report.");
            }
            const result = await response.json();
            if (!result || result.ok !== true || !Array.isArray(result.rows) || result.rows.length === 0) {
                throw new Error("The local checker returned an incomplete report.");
            }
            renderResult(result);
        } catch {
            element("check-status").textContent = "Check could not finish";
            element("check-detail").textContent = "The local session may have expired or already been used, or this browser may block the probe. Keep your privacy settings as they are. Open a new Browser Check from Health to try again.";
            element("status-icon").textContent = "!";
            element("status-icon").className = "status-icon status-unavailable";
        } finally {
            window.clearTimeout(timeout);
        }
    }

    run();
})();
