/**
 * MoneyFlow — Main JavaScript
 *
 * Client-side validation as a UX supplement.
 * Server-side validation is the authoritative source of truth.
 */

'use strict';

// Password strength indicator on register page
(function () {
    const pwdInput = document.getElementById('password');
    const confInput = document.getElementById('confirm_password');

    if (!pwdInput) return;

    function checkStrength(value) {
        const checks = [
            value.length >= 8,
            /[A-Z]/.test(value),
            /[a-z]/.test(value),
            /[0-9]/.test(value),
            /[@#$%&*!^()_\-+=\[\]{};:'",.<>?\\/|`~]/.test(value),
        ];
        return checks.filter(Boolean).length;
    }

    pwdInput.addEventListener('input', function () {
        const score = checkStrength(this.value);
        const small = this.parentElement.querySelector('small');
        if (!small) return;
        const labels = ['', 'Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
        small.textContent = this.value.length > 0
            ? 'Strength: ' + (labels[score] || 'Strong')
            : 'Min 8 chars: uppercase, lowercase, digit, special character';
    });

    if (confInput) {
        confInput.addEventListener('input', function () {
            if (this.value && this.value !== pwdInput.value) {
                this.setCustomValidity('Passwords do not match.');
            } else {
                this.setCustomValidity('');
            }
        });
    }
}());

// Confirm destructive actions
(function () {
    document.querySelectorAll('[data-confirm]').forEach(function (el) {
        el.addEventListener('click', function (e) {
            if (!window.confirm(el.dataset.confirm)) {
                e.preventDefault();
            }
        });
    });
}());

// Pre-fill recipient field from URL query string on transfer page
(function () {
    const recipientInput = document.getElementById('recipient');
    if (!recipientInput) return;
    const params = new URLSearchParams(window.location.search);
    const r = params.get('recipient');
    if (r && !recipientInput.value) {
        recipientInput.value = r;
    }
}());
