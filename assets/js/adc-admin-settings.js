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

    // Init and Bind
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

    // Init and Bind
    if ($captchaSelect.length) {
        toggleCaptcha();
        $captchaSelect.on('change', toggleCaptcha);
    }
});
