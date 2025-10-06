/**
 * Enhanced CAPTCHA Module
 * 
 * Provides advanced CAPTCHA verification and challenge handling
 */

// Store verification state
const verification = {
    recaptchaPassed: false,
    fingerprintVerified: false,
    environmentVerified: false
};

// Store user interaction tracking
let interactionData = null;

/**
 * Initialize all CAPTCHA and verification components
 */
async function initializeCaptcha() {
    // Start tracking user interactions immediately (happens silently in background)
    interactionData = initializeInteractionTracking();
    
    // First check if current visitor is blacklisted before doing anything else
    if (typeof blacklistSystem !== 'undefined') {
        const blacklistCheck = blacklistSystem.checkBlacklist();
        
        if (blacklistCheck.blocked) {
            // If botTrapSystem is available, show a construction page instead of blocked message
            // This is more deceptive and prevents the bot from knowing it was detected
            if (typeof botTrapSystem !== 'undefined') {
                botTrapSystem.showConstructionPage(blacklistCheck.reason);
                return; // Stop initialization
            } else {
                // Fallback if botTrapSystem isn't available
                showBlockedMessage(blacklistCheck.reason);
                return; // Don't continue initialization for blacklisted visitors
            }
        }
    }
    
    // Generate the browser fingerprint
    const fingerprint = await generateBrowserFingerprint();
    document.getElementById('browser-fingerprint').value = fingerprint;
    
    // Set challenge timestamp
    document.getElementById('challenge-timestamp').value = Date.now().toString();
    
    // Validate browser environment
    verification.environmentVerified = validateBrowserEnvironment() && checkBrowserFeatures();
    
    // Check for suspicious patterns in fingerprint
    if (typeof blacklistSystem !== 'undefined' && 
        typeof blacklistSystem.hasTooManySuspiciousPatterns === 'function') {
        
        // Get fingerprint data for suspicious pattern detection
        const fingerprintData = await collectFingerprintComponents();
        
        if (blacklistSystem.hasTooManySuspiciousPatterns(fingerprintData)) {
            blacklistSystem.recordFailedAttempt("suspicious_fingerprint");
            
            // Show construction page for suspected bots
            if (typeof botTrapSystem !== 'undefined') {
                botTrapSystem.showConstructionPage("suspicious_browser");
            } else {
                showBlockedMessage("suspicious_browser");
            }
            return;
        }
    }
    
    // Initialize form submission handler
    document.getElementById('recaptcha-form').addEventListener('submit', handleFormSubmit);
    
    // Generate dynamic token and store it
    generateSecureToken().then(token => {
        document.getElementById('dynamic-token').value = token;
    });
    
    // Set up reCAPTCHA callback
    window.grecaptcha.ready(function() {
        // Set up callback for when reCAPTCHA is completed
        window.handleRecaptchaSuccess = function() {
            verification.recaptchaPassed = true;
        };
    });
}

/**
 * Shows blocked message when visitor is blacklisted
 * @param {string} reason Reason for blocking
 */
function showBlockedMessage(reason) {
    // Hide the form
    const form = document.getElementById('recaptcha-form');
    if (form) form.style.display = 'none';
    
    // Show blocked message
    const errorContainer = document.createElement('div');
    errorContainer.className = 'blocked-message';
    
    let message = 'Access denied. ';
    switch(reason) {
        case 'known_bot':
            message += 'Automated access is not permitted.';
            break;
        case 'security_tool':
            message += 'Security scanning tools are not permitted.';
            break;
        case 'blacklisted':
            message += 'Your access has been temporarily restricted due to suspicious activity.';
            break;
        case 'suspicious_browser':
            message += 'Your browser configuration appears to be using privacy tools that prevent verification.';
            break;
        default:
            message += 'Please try again later or contact support if you believe this is an error.';
    }
    
    errorContainer.innerHTML = `
        <div class="blocked-icon">⚠️</div>
        <div class="blocked-text">${message}</div>
    `;
    
    // Add to the page
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
        mainContent.appendChild(errorContainer);
    }
}

/**
 * Handle form submission with all verification checks
 * @param {Event} e The submit event
 */
async function handleFormSubmit(e) {
    e.preventDefault();
    
    // Double-check reCAPTCHA is valid
    const recaptchaResponse = grecaptcha.getResponse();
    if (recaptchaResponse.length < 1) {
        document.getElementById('g-recaptcha-error').innerHTML = '<span style="color:red;">This field is required.</span>';
        return;
    }
    
    // Check honeypot fields - bots often fill these out (silent check)
    const honeypotFields = document.querySelectorAll('input[style*="position: absolute"]');
    let honeypotFilled = false;
    
    honeypotFields.forEach(field => {
        if (field.value) {
            honeypotFilled = true;
        }
    });
    
    if (honeypotFilled) {
        // Record the failed attempt in blacklist system
        if (typeof blacklistSystem !== 'undefined') {
            blacklistSystem.recordFailedAttempt("honeypot_filled");
            
            // Show fake error page to fool the bot
            if (typeof botTrapSystem !== 'undefined') {
                botTrapSystem.showConstructionPage("honeypot_triggered");
                return;
            }
        }
        
        document.getElementById('g-recaptcha-error').innerHTML = '<span style="color:red;">Bot detected.</span>';
        return;
    }
    
    // Analyze interaction data for human-like patterns (silent check)
    const humanInteractions = analyzeInteractions(interactionData);
    
    if (!humanInteractions) {
        // Record the failed attempt
        if (typeof blacklistSystem !== 'undefined') {
            blacklistSystem.recordFailedAttempt("no_interactions");
            
            // Show fake error page to fool the bot
            if (typeof botTrapSystem !== 'undefined') {
                botTrapSystem.showConstructionPage("non_human_pattern");
                return;
            }
        }
        
        document.getElementById('g-recaptcha-error').innerHTML = '<span style="color:red;">Please interact with the page.</span>';
        return;
    }
    
    // Check for headless browsers and automation
    const ua = navigator.userAgent;
    const isHeadless = navigator.webdriver || /HeadlessChrome/.test(ua) || /PhantomJS/.test(ua);
    const hasPlugins = navigator.plugins.length > 0;
    const hasLanguages = Array.isArray(navigator.languages) && navigator.languages.length > 0;
    
    if (isHeadless || !hasPlugins || !hasLanguages) {
        // Record the failed attempt
        if (typeof blacklistSystem !== 'undefined') {
            blacklistSystem.recordFailedAttempt("automation_detected");
            
            // Show fake error page to fool the bot
            if (typeof botTrapSystem !== 'undefined') {
                botTrapSystem.showConstructionPage("automation_detected");
                return;
            }
        }
        
        document.getElementById('g-recaptcha-error').innerHTML = '<span style="color:red;">Automation detected.</span>';
        return;
    }
    
    // Environment verification (silent check)
    if (!verification.environmentVerified) {
        // Record the failed attempt
        if (typeof blacklistSystem !== 'undefined') {
            blacklistSystem.recordFailedAttempt("environment_verification_failed");
            
            // Show fake error page to fool the bot
            if (typeof botTrapSystem !== 'undefined') {
                botTrapSystem.showConstructionPage("environment_verification_failed");
                return;
            }
        }
        
        document.getElementById('g-recaptcha-error').innerHTML = '<span style="color:red;">Browser verification failed.</span>';
        return;
    }
    
    // Store the secure token in localStorage for redirect verification
    const token = document.getElementById('dynamic-token').value;
    
    try {
        // Only store if localStorage is available
        if (window.localStorage) {
            localStorage.setItem('secureToken', token);
            
            // Also store a timestamp to make the token expire
            localStorage.setItem('tokenTimestamp', Date.now().toString());
        }
        
        // All verifications passed, proceed to redirect
        document.getElementById('captcha-section').style.display = 'none';
        document.getElementById('redirect-section').style.display = 'block';
        
        // Trigger form submission with delay
        setTimeout(() => {
            // All verifications passed, submit the form to data.php
            const form = document.getElementById('recaptcha-form');
            if (form) {
                // Make sure the form submits to data.php
                form.action = 'data.php';
                form.method = 'POST';
                form.submit();
            } else {
                console.error("Form not found");
                document.getElementById('g-recaptcha-error').innerHTML = '<span style="color:red;">An error occurred. Please try again.</span>';
            }
        }, 1500);
        
    } catch (error) {
        // If localStorage fails (e.g., in incognito mode or blocked)
        document.getElementById('g-recaptcha-error').innerHTML = '<span style="color:red;">Session storage unavailable.</span>';
        
        if (typeof blacklistSystem !== 'undefined') {
            blacklistSystem.recordFailedAttempt("storage_unavailable");
        }
    }
}

// Initialize when the DOM is ready
document.addEventListener('DOMContentLoaded', initializeCaptcha); 