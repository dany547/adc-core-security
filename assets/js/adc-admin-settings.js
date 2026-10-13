jQuery(document).ready(function ($) {
    // --- Brute Force Logic ---
    var $bfCheckbox = $('input[name="adc_security_options[brute_force_protection]"]');
    var $bfRows = $('input[name="adc_security_options[bf_max_attempts]"], input[name="adc_security_options[bf_lockout_duration]"], input[name="adc_security_options[login_notification]"]').closest('tr');

    function toggleBruteForce() {
        if ($bfCheckbox.is(':checked')) {
            $bfRows.show();
        } else {
            $bfRows.hide();
        }
    }

    if ($bfCheckbox.length) {
        toggleBruteForce();
        $bfCheckbox.on('change', toggleBruteForce);
    }

    // --- Captcha Logic ---
    var $captchaSelect = $('select[name="adc_security_options[captcha_type]"]');
    var $turnstileRows = $('input[name="adc_security_options[turnstile_site_key]"], input[name="adc_security_options[turnstile_secret_key]"]').closest('tr');

    function toggleCaptcha() {
        var val = $captchaSelect.val();
        if (val === 'turnstile') {
            $turnstileRows.show();
        } else {
            $turnstileRows.hide();
        }
    }

    if ($captchaSelect.length) {
        toggleCaptcha();
        $captchaSelect.on('change', toggleCaptcha);
    }

    // --- Session Expiration Logic ---
    var $sessionCheckbox = $('input[name="adc_security_options[admin_session_expiration_enabled]"]');
    var $sessionDaysRow = $('input[name="adc_security_options[admin_session_expiration_days]"]').closest('tr');

    function toggleSessionExpiration() {
        if ($sessionCheckbox.is(':checked')) {
            $sessionDaysRow.show();
        } else {
            $sessionDaysRow.hide();
        }
    }

    if ($sessionCheckbox.length) {
        toggleSessionExpiration();
        $sessionCheckbox.on('change', toggleSessionExpiration);
    }

    // --- Security headers: show only the controls that apply ---
    // Every control is still submitted when hidden, so the form works without JS.
    var cspData = window.adcSecurityCsp || {};
    var headerRowClasses = {
        referrer_policy: '.adc-field-referrer_policy',
        permissions_policy: '.adc-field-permissions_policy',
        hsts: '.adc-field-hsts'
    };

    // Must match the fixed tail that ADC_Security_Csp_Policy::build_generated() appends.
    var cspFixedTail = ["frame-ancestors 'self'", "base-uri 'self'", "form-action 'self'", "object-src 'none'"];

    function optionValue(name) {
        var $inputs = $('[name="adc_security_options[' + name + ']"]');
        var $checked = $inputs.filter(':checked');
        return $checked.length ? $checked.val() : $inputs.first().val();
    }

    function headerEnabled(key) {
        return $('input[name="adc_security_options[security_header_toggles][]"][value="' + key + '"]').is(':checked');
    }

    function updateHeaderRows() {
        Object.keys(headerRowClasses).forEach(function (key) {
            $(headerRowClasses[key]).toggle(headerEnabled(key));
        });
    }

    // Mirror of build_generated(): defaults, then presets, then extras, then removals.
    function buildCspPreview() {
        var directives = cspData.directives || [];
        var defaults = cspData.defaults || {};
        var presets = cspData.presets || {};
        var map = {};

        function addSources(dir, sources) {
            if (!map.hasOwnProperty(dir)) {
                map[dir] = [];
            }
            sources.forEach(function (src) {
                if (map[dir].indexOf(src) === -1) {
                    map[dir].push(src);
                }
            });
        }

        Object.keys(defaults).forEach(function (dir) {
            addSources(dir, defaults[dir]);
        });

        $('input[name="adc_security_options[csp_presets][]"]:checked').each(function () {
            var preset = presets[this.value];
            if (!preset) {
                return;
            }
            Object.keys(preset.directives).forEach(function (dir) {
                addSources(dir, preset.directives[dir]);
            });
        });

        directives.forEach(function (dir) {
            var extra = $('textarea[name="adc_security_options[csp_extra_sources][' + dir + ']"]').val() || '';
            var sources = extra.split(/[\s,]+/).filter(function (s) { return s !== ''; });
            if (sources.length) {
                addSources(dir, sources);
            }
        });

        directives.forEach(function (dir) {
            if (!map.hasOwnProperty(dir)) {
                return;
            }
            $('input[name="adc_security_options[csp_removed_defaults][' + dir + '][]"]:checked').each(function () {
                var src = this.value;
                if (dir === 'default-src' && src === "'self'") {
                    return;
                }
                map[dir] = map[dir].filter(function (s) { return s !== src; });
            });
        });

        var parts = [];
        directives.forEach(function (dir) {
            if (!map.hasOwnProperty(dir)) {
                return;
            }
            var list = map[dir].length ? map[dir] : ["'none'"];
            parts.push(dir + ' ' + list.join(' '));
        });

        return parts.concat(cspFixedTail).join('; ') + ';';
    }

    function updateConditionalPanels() {
        $('[data-adc-when]').each(function () {
            var $panel = $(this);
            var allowed = String($panel.attr('data-adc-values')).split(' ');
            $panel.toggle(allowed.indexOf(optionValue($panel.attr('data-adc-when'))) !== -1);
        });

        if ($('#adc-csp-preview').length) {
            $('#adc-csp-preview').text(buildCspPreview());
        }
    }

    if ($('.adc-csp').length) {
        updateHeaderRows();
        updateConditionalPanels();

        $('input[name="adc_security_options[security_header_toggles][]"]').on('change', updateHeaderRows);
        $('.adc-csp').on('change input', 'input, textarea, select', updateConditionalPanels);
    }

    // --- CSP site scanner: select all / none (progressive enhancement) ---
    // The helper row is hidden in the markup and only shown when this script runs.
    var $scanForm = $('#adc-csp-apply-form');
    if ($scanForm.length) {
        $scanForm.find('.adc-csp-select-row').prop('hidden', false);
        $scanForm.on('click', '[data-adc-select]', function () {
            var selectAll = $(this).attr('data-adc-select') === 'all';
            // Disabled boxes (already allowed, or loaded over http) are never changed.
            $scanForm.find('input[type="checkbox"]:not(:disabled)').prop('checked', selectAll);
        });
    }

    // --- Firewall: confirm before switching from Log only to Block ---
    $(document).on('submit', 'form[data-adc-confirm-block]', function (event) {
        var $form = $(this);
        var wasMonitor = $form.attr('data-adc-was-mode') === 'monitor';
        var goingBlock = $form.find('input[name="mode"]:checked').val() === 'enforce';
        if (wasMonitor && goingBlock && !window.confirm($form.attr('data-adc-confirm-block'))) {
            event.preventDefault();
        }
    });

    $('.adc-fw-form').each(function () {
        $(this).attr('data-adc-was-mode', $(this).find('input[name="mode"]:checked').val() || 'monitor');
    });
});
