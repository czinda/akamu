// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Mermaid theme variables derived from synta.css for each mdBook theme.
// Colors are taken directly from the CSS variable definitions in synta.css so
// that diagrams match the page background, text, border, and link colours.

(() => {
    // ── Per-theme variable maps ───────────────────────────────────────────────
    // Keys match the CSS class that mdBook places on <html>.
    // Values become Mermaid themeVariables (theme: 'base').

    const themes = {
        // ── Light ──────────────────────────────────────────────────────────────
        light: {
            background:            '#f8fafc',  // --bg
            primaryColor:          '#e0f2fe',  // light blue node fill (quote-bg tint)
            primaryBorderColor:    '#0284c7',  // --quote-border (sky blue)
            primaryTextColor:      '#0f172a',  // --fg
            secondaryColor:        '#f1f5f9',  // --table-header-bg
            tertiaryColor:         '#e2e8f0',  // --table-border-color (used for 3rd fill)
            edgeLabelBackground:   '#f8fafc',  // --bg
            clusterBkg:            '#f1f5f9',  // --table-header-bg
            clusterBorder:         '#cbd5e1',  // --scrollbar
            lineColor:             '#1d4ed8',  // --links
            textColor:             '#0f172a',  // --fg
            // sequence diagram
            actorBkg:              '#f1f5f9',  // --table-header-bg
            actorBorder:           '#cbd5e1',  // --scrollbar
            actorTextColor:        '#0f172a',  // --fg
            actorLineColor:        '#94a3b8',  // --sidebar-non-existant
            signalColor:           '#1d4ed8',  // --links
            signalTextColor:       '#0f172a',  // --fg
            labelBoxBkgColor:      '#e0f2fe',  // light node fill
            labelBoxBorderColor:   '#0284c7',  // --quote-border
            labelTextColor:        '#0f172a',  // --fg
            loopTextColor:         '#0f172a',  // --fg
            noteBkgColor:          '#fef9c3',  // warm yellow note
            noteBorderColor:       '#d97706',  // --warning-border
            noteTextColor:         '#0f172a',  // --fg
            activationBorderColor: '#0284c7',  // --quote-border
            activationBkgColor:    '#bfdbfe',  // --search-mark-bg
        },

        // ── Rust ───────────────────────────────────────────────────────────────
        rust: {
            background:            '#fdf5ed',  // --bg
            primaryColor:          '#fef5e6',  // --quote-bg
            primaryBorderColor:    '#d94f00',  // --quote-border (rust red)
            primaryTextColor:      '#1c0e00',  // --fg
            secondaryColor:        '#f3e8d8',  // --table-header-bg
            tertiaryColor:         '#e8d5bc',  // --sidebar-spacer
            edgeLabelBackground:   '#fdf5ed',  // --bg
            clusterBkg:            '#f5e8d4',  // --code-bg
            clusterBorder:         '#c8a88a',  // --scrollbar
            lineColor:             '#a52b00',  // --links
            textColor:             '#1c0e00',  // --fg
            // sequence diagram
            actorBkg:              '#f3e8d8',  // --table-header-bg
            actorBorder:           '#c8a88a',  // --scrollbar
            actorTextColor:        '#1c0e00',  // --fg
            actorLineColor:        '#a07850',  // --sidebar-non-existant
            signalColor:           '#a52b00',  // --links
            signalTextColor:       '#1c0e00',  // --fg
            labelBoxBkgColor:      '#fef5e6',  // --quote-bg
            labelBoxBorderColor:   '#d94f00',  // --quote-border
            labelTextColor:        '#1c0e00',  // --fg
            loopTextColor:         '#1c0e00',  // --fg
            noteBkgColor:          '#fef5e6',  // --quote-bg
            noteBorderColor:       '#c05a00',  // --warning-border
            noteTextColor:         '#1c0e00',  // --fg
            activationBorderColor: '#d94f00',  // --quote-border
            activationBkgColor:    '#ffd59e',  // --search-mark-bg
        },

        // ── Navy ───────────────────────────────────────────────────────────────
        navy: {
            background:            '#131d2e',  // --bg
            primaryColor:          '#162236',  // --table-header-bg / quote-bg
            primaryBorderColor:    '#3b82f6',  // --quote-border (blue)
            primaryTextColor:      '#d4e0f0',  // --fg
            secondaryColor:        '#1b2d46',  // --sidebar-spacer
            tertiaryColor:         '#0c1525',  // --sidebar-bg
            edgeLabelBackground:   '#131d2e',  // --bg
            clusterBkg:            '#0e1a2b',  // --code-bg
            clusterBorder:         '#24395a',  // --table-border-color
            lineColor:             '#60a5fa',  // --links
            textColor:             '#d4e0f0',  // --fg
            // sequence diagram
            actorBkg:              '#162236',  // --table-header-bg
            actorBorder:           '#2a4460',  // --scrollbar
            actorTextColor:        '#d4e0f0',  // --fg
            actorLineColor:        '#3a5474',  // --sidebar-non-existant
            signalColor:           '#60a5fa',  // --links
            signalTextColor:       '#d4e0f0',  // --fg
            labelBoxBkgColor:      '#162236',  // --quote-bg
            labelBoxBorderColor:   '#3b82f6',  // --quote-border
            labelTextColor:        '#d4e0f0',  // --fg
            loopTextColor:         '#d4e0f0',  // --fg
            noteBkgColor:          '#162236',  // --table-header-bg
            noteBorderColor:       '#f59e0b',  // --warning-border
            noteTextColor:         '#d4e0f0',  // --fg
            activationBorderColor: '#3b82f6',  // --quote-border
            activationBkgColor:    '#1e3a8a',  // --search-mark-bg
        },

        // ── Coal ───────────────────────────────────────────────────────────────
        coal: {
            background:            '#1a1c21',  // --bg
            primaryColor:          '#1c2030',  // --quote-bg
            primaryBorderColor:    '#4299e1',  // --quote-border (blue)
            primaryTextColor:      '#d4dae5',  // --fg
            secondaryColor:        '#252932',  // --sidebar-spacer
            tertiaryColor:         '#121418',  // --sidebar-bg
            edgeLabelBackground:   '#1a1c21',  // --bg
            clusterBkg:            '#14161b',  // --code-bg
            clusterBorder:         '#2d3748',  // --table-border-color
            lineColor:             '#63b3ed',  // --links
            textColor:             '#d4dae5',  // --fg
            // sequence diagram
            actorBkg:              '#1e2029',  // --table-header-bg
            actorBorder:           '#374151',  // --scrollbar
            actorTextColor:        '#d4dae5',  // --fg
            actorLineColor:        '#4a5568',  // --sidebar-non-existant
            signalColor:           '#63b3ed',  // --links
            signalTextColor:       '#d4dae5',  // --fg
            labelBoxBkgColor:      '#1c2030',  // --quote-bg
            labelBoxBorderColor:   '#4299e1',  // --quote-border
            labelTextColor:        '#d4dae5',  // --fg
            loopTextColor:         '#d4dae5',  // --fg
            noteBkgColor:          '#1e2029',  // --table-header-bg
            noteBorderColor:       '#f6ad55',  // --warning-border
            noteTextColor:         '#d4dae5',  // --fg
            activationBorderColor: '#4299e1',  // --quote-border
            activationBkgColor:    '#1e3a8a',  // --search-mark-bg
        },

        // ── Ayu ────────────────────────────────────────────────────────────────
        ayu: {
            background:            '#0d1017',  // --bg
            primaryColor:          '#0f141e',  // --quote-bg
            primaryBorderColor:    '#e6b450',  // --quote-border (golden)
            primaryTextColor:      '#cccac2',  // --fg
            secondaryColor:        '#14171f',  // --sidebar-spacer
            tertiaryColor:         '#08090f',  // --sidebar-bg
            edgeLabelBackground:   '#0d1017',  // --bg
            clusterBkg:            '#080c12',  // --code-bg
            clusterBorder:         '#1e2433',  // --table-border-color
            lineColor:             '#e6b450',  // --links (golden)
            textColor:             '#cccac2',  // --fg
            // sequence diagram
            actorBkg:              '#10151f',  // --table-header-bg
            actorBorder:           '#1e2433',  // --scrollbar
            actorTextColor:        '#cccac2',  // --fg
            actorLineColor:        '#3d4552',  // --sidebar-non-existant
            signalColor:           '#e6b450',  // --links
            signalTextColor:       '#cccac2',  // --fg
            labelBoxBkgColor:      '#0f141e',  // --quote-bg
            labelBoxBorderColor:   '#e6b450',  // --quote-border
            labelTextColor:        '#cccac2',  // --fg
            loopTextColor:         '#cccac2',  // --fg
            noteBkgColor:          '#10151f',  // --table-header-bg
            noteBorderColor:       '#ff8f40',  // --warning-border
            noteTextColor:         '#cccac2',  // --fg
            activationBorderColor: '#e6b450',  // --quote-border
            activationBkgColor:    '#3d2e00',  // --search-mark-bg
        },
    };

    const darkThemeNames  = ['ayu', 'navy', 'coal'];
    const lightThemeNames = ['light', 'rust'];

    // ── Detect current mdBook theme from <html> class list ────────────────────

    function detectTheme() {
        const classes = document.getElementsByTagName('html')[0].classList;
        for (const name of Object.keys(themes)) {
            if (classes.contains(name)) return name;
        }
        // Fallback: pick light/dark based on any known class.
        for (const cls of classes) {
            if (darkThemeNames.includes(cls))  return 'navy';
            if (lightThemeNames.includes(cls)) return 'light';
        }
        return 'light';
    }

    // ── Initialize Mermaid ────────────────────────────────────────────────────

    const currentTheme = detectTheme();
    const isDark = darkThemeNames.includes(currentTheme);

    mermaid.initialize({
        startOnLoad: true,
        theme: 'base',
        themeVariables: themes[currentTheme] ?? themes.light,
        // Inherit the page font so diagrams feel native, not bolted-on.
        fontFamily: 'inherit',
        // Slightly larger base font so labels stay readable at all viewport sizes.
        fontSize: 15,
        flowchart: { htmlLabels: true, curve: 'basis', padding: 20, nodeSpacing: 60, rankSpacing: 60 },
        sequence:  { actorMargin: 60, messageMargin: 40, mirrorActors: false },
        er:        { layoutDirection: 'TB', minEntityWidth: 120 },
        gantt:     { barHeight: 28, barGap: 6, topPadding: 50 },
    });

    // ── Reload on theme switch so Mermaid SVGs are redrawn ───────────────────
    // mdBook theme buttons are <button id="<theme-name>">.

    const allThemeNames = [...darkThemeNames, ...lightThemeNames];
    for (const name of allThemeNames) {
        const btn = document.getElementById(name);
        if (!btn) continue;
        btn.addEventListener('click', () => {
            // Only reload when crossing the current theme boundary.
            if (name !== currentTheme) window.location.reload();
        });
    }
})();
