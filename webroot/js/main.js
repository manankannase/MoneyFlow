/**
 * MoneyFlow - Main JavaScript Module
 * Handles client-side interactions and form validation
 */

document.addEventListener('DOMContentLoaded', function() {
    initializeFormValidation();
    initializeUI();
    initializePasswordToggles();
    initializeTransferForm();
});

/**
 * Initialize password toggle buttons
 */
function initializePasswordToggles() {
    const toggleButtons = document.querySelectorAll('.password-toggle');
    
    toggleButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            const container = this.closest('.password-container');
            if (!container) return;
            
            const field = container.querySelector('input[type="password"], input[type="text"]');
            if (!field) return;
            
            if (field.type === 'password') {
                field.type = 'text';
                this.textContent = 'Hide';
                this.classList.add('password-visible');
            } else {
                field.type = 'password';
                this.textContent = 'Show';
                this.classList.remove('password-visible');
            }
        });
    });
}

/**
 * Initialize form validation
 */
function initializeFormValidation() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!validateFormInputs(this)) {
                e.preventDefault();
            }
        });
    });
}

/**
 * Validate form inputs
 */
function validateFormInputs(form) {
    const inputs = form.querySelectorAll('[required]');
    let isValid = true;

    inputs.forEach(input => {
        if (input.type === 'email') {
            if (!validateEmail(input.value)) {
                showFieldError(input, 'Please enter a valid email');
                isValid = false;
            } else {
                clearFieldError(input);
            }
        } else if (input.value.trim() === '') {
            showFieldError(input, 'This field is required');
            isValid = false;
        } else {
            clearFieldError(input);
        }
    });

    return isValid;
}

/**
 * Validate email format
 */
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Show field error
 */
function showFieldError(field, message) {
    field.classList.add('input-error');
    let errorElement = field.nextElementSibling;
    
    if (!errorElement || !errorElement.classList.contains('field-error')) {
        errorElement = document.createElement('small');
        errorElement.className = 'field-error';
        field.parentNode.insertBefore(errorElement, field.nextSibling);
    }
    
    errorElement.textContent = message;
}

/**
 * Clear field error
 */
function clearFieldError(field) {
    field.classList.remove('input-error');
    const errorElement = field.nextElementSibling;
    if (errorElement && errorElement.classList.contains('field-error')) {
        errorElement.remove();
    }
}

/**
 * Initialize UI interactions
 */
function initializeUI() {
    // Ensure transfer panels are always hidden on page load.
    // The browser's back-forward cache can restore them as visible.
    const confirmPanel = document.getElementById('confirmPanel');
    if (confirmPanel) confirmPanel.style.display = 'none';
    const transferErrorPanel = document.getElementById('transferErrorPanel');
    if (transferErrorPanel) transferErrorPanel.style.display = 'none';

    // Auto-dismiss alerts after 5 seconds.
    // Exclude #confirmPanel — it is controlled exclusively by initializeTransferForm.
    const alerts = document.querySelectorAll('.alert:not(#confirmPanel)');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });

    // Handle number formatting
    const amountInputs = document.querySelectorAll('input[name="transfer_amount"]');
    amountInputs.forEach(input => {
        input.addEventListener('blur', function() {
            if (this.value) {
                this.value = parseFloat(this.value).toFixed(2);
            }
        });
    });
}

/**
 * Format currency values
 */
function formatCurrency(value) {
    return '₹' + parseFloat(value).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/**
 * Format date
 */
function formatDate(dateString) {
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return new Date(dateString).toLocaleDateString('en-IN', options);
}

/**
 * Transfer form: AES-256-GCM token fetch
 *
 * Intercepts the transfer form submission and calls /api_transfer_signature.php
 * with the recipient_id and amount. The server validates these values, encrypts
 * them (along with sender_id, nonce, and timestamp) into an AES-256-GCM token,
 * and returns the opaque ciphertext blob.
 *
 * The JS places this token in the hidden `transfer_token` field and re-submits.
 * The server decrypts the token and uses ONLY the decrypted values — the POST
 * recipient_id and amount fields are ignored for business logic.
 *
 * Why Burp cannot tamper with the token:
 *   AES-256-GCM provides authenticated encryption. Any modification to the
 *   ciphertext causes the GCM authentication tag check to fail on the server,
 *   and the transfer is rejected before any values are read.
 */
function initializeTransferForm() {
    const transferForm = document.getElementById('transferForm');
    if (!transferForm) return;

    let tokenReady = false;
    const errorPanel = document.getElementById('transferErrorPanel');

    function showTransferError(msg) {
        if (!errorPanel) return;
        errorPanel.textContent = msg;
        errorPanel.style.display = 'block';
    }

    function clearTransferError() {
        if (!errorPanel) return;
        errorPanel.style.display = 'none';
        errorPanel.textContent = '';
    }

    transferForm.addEventListener('submit', async function (event) {
        // Second pass (token already in hidden field): let form submit normally
        if (tokenReady) {
            tokenReady = false;
            return;
        }

        if (event.defaultPrevented) return;
        event.preventDefault();

        clearTransferError();

        const recipientId = document.getElementById('recipient_id').value.trim();
        const amountRaw   = document.getElementById('transfer_amount').value.trim();
        const submitBtn   = this.querySelector('button[type="submit"]');

        if (!recipientId || !amountRaw) {
            showTransferError('Please fill in all required fields.');
            return;
        }

        const numAmount = parseFloat(amountRaw);
        if (isNaN(numAmount) || numAmount <= 0) {
            showTransferError('Please enter a valid amount greater than 0.');
            return;
        }

        submitBtn.disabled    = true;
        submitBtn.textContent = 'Securing transfer...';

        try {
            const csrfToken = transferForm.querySelector('input[name="csrf_token"]').value;

            // Single API call: server validates recipient + amount, returns AES-256-GCM token.
            // The token is opaque — client cannot read or modify its contents.
            const body = new URLSearchParams();
            body.append('csrf_token',      csrfToken);
            body.append('recipient_id',    recipientId);
            body.append('transfer_amount', numAmount.toFixed(2));

            const response = await fetch('/api_transfer_signature.php', {
                method:      'POST',
                credentials: 'same-origin',
                headers:     { 'Content-Type': 'application/x-www-form-urlencoded' },
                body:        body.toString()
            });

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                throw new Error(errData.error || 'Server returned ' + response.status);
            }

            const data = await response.json();
            if (!data.success) {
                throw new Error(data.error || 'Transfer request failed.');
            }

            // Place the encrypted token (containing opaque transaction_id) into hidden field.
            // The server will decrypt it, get the transaction_id, and look up the DB row.
            // Strip name attributes from recipient_id and transfer_amount so they are absent
            // from the final POST entirely — the DB row is the authoritative source.
            document.getElementById('transfer_token').value = data.token;
            document.getElementById('recipient_id').removeAttribute('name');
            document.getElementById('transfer_amount').removeAttribute('name');

            // Show confirmation panel so the user sees what they're about to send.
            // Values come from the server response (what was stored in DB), not the form.
            const confirmPanel = document.getElementById('confirmPanel');
            if (confirmPanel) {
                document.getElementById('confirmAmount').textContent    = '₹' + numAmount.toFixed(2);
                document.getElementById('confirmRecipient').textContent = data.recipient_name || recipientId;
                confirmPanel.style.display = 'block';
            }

            tokenReady            = true;
            submitBtn.disabled    = false;
            submitBtn.textContent = 'Confirm & Send';
            // Do NOT auto-submit — user must click the button again to confirm
            // This gives them a chance to see the confirmation panel and cancel if tampered

        } catch (error) {
            console.error('Transfer token fetch failed:', error);
            showTransferError(error.message || 'Could not complete the transfer. Please try again.');
            submitBtn.disabled    = false;
            submitBtn.textContent = 'Send Money';
        }
    });
}


