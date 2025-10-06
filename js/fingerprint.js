/**
 * Browser Fingerprinting Module
 * 
 * Advanced fingerprinting techniques to identify browser environments
 * and detect automation tools, headless browsers, and sandboxes
 */

/**
 * Generates a browser fingerprint using multiple techniques
 * @returns {Promise<string>} A unique browser fingerprint hash
 */
async function generateBrowserFingerprint() {
    try {
        const fingerprints = await collectFingerprintComponents();
        const fingerprintStr = JSON.stringify(fingerprints);
        
        // Hash the fingerprint data
        const encoder = new TextEncoder();
        const data = encoder.encode(fingerprintStr);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        
        // Convert to hex string
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
            
        return hashHex;
    } catch (error) {
        // Fallback if advanced fingerprinting fails
        return generateFallbackFingerprint();
    }
}

/**
 * Fallback fingerprinting method using less advanced techniques
 * @returns {string} A simple fingerprint
 */
function generateFallbackFingerprint() {
    const components = [
        navigator.userAgent,
        navigator.language,
        screen.colorDepth,
        screen.width + 'x' + screen.height,
        new Date().getTimezoneOffset(),
        !!navigator.cookieEnabled,
        typeof(window.sessionStorage) !== 'undefined',
        typeof(window.localStorage) !== 'undefined'
    ];
    
    return btoa(components.join('###'));
}

/**
 * Collects various browser attributes for fingerprinting
 * @returns {Promise<Object>} Collection of fingerprinting data
 */
async function collectFingerprintComponents() {
    const components = {
        // Basic info
        userAgent: navigator.userAgent,
        language: navigator.language,
        languages: navigator.languages,
        platform: navigator.platform,
        cores: navigator.hardwareConcurrency || 0,
        deviceMemory: navigator.deviceMemory || 0,
        
        // Screen properties
        screenRes: `${screen.width}x${screen.height}`,
        colorDepth: screen.colorDepth,
        pixelRatio: window.devicePixelRatio || 1,
        
        // Time and locale
        timezone: new Date().getTimezoneOffset(),
        timezoneStr: Intl.DateTimeFormat().resolvedOptions().timeZone,
        
        // Feature detection
        touchPoints: navigator.maxTouchPoints || 0,
        cookiesEnabled: navigator.cookieEnabled,
        localStorage: !!window.localStorage,
        sessionStorage: !!window.sessionStorage,
        indexedDB: !!window.indexedDB,
        
        // Browser features
        doNotTrack: navigator.doNotTrack || navigator.msDoNotTrack,
        adBlocker: false,  // Will be set by detection function
        
        // Audio/video capabilities
        audioCodecs: detectAudioCodecs(),
        videoCodecs: detectVideoCodecs(),
        
        // WebGL info
        webglVendor: null,
        webglRenderer: null,
        
        // Canvas fingerprint
        canvasHash: await generateCanvasFingerprint(),
        
        // Font detection
        fonts: detectFonts(),
        
        // Battery info
        batteryInfo: await getBatteryInfo(),
        
        // Connection info
        connectionType: getConnectionType(),
        
        // Plugins info (often missing in headless browsers)
        plugins: getPluginsInfo(),
        
        // CPU benchmarking (headless browsers often show different performance characteristics)
        performanceMetrics: benchmarkPerformance()
    };
    
    // Add WebGL info
    try {
        const webglInfo = getWebGLInfo();
        components.webglVendor = webglInfo.vendor;
        components.webglRenderer = webglInfo.renderer;
    } catch (e) {
        // WebGL might be disabled
    }
    
    // Detect ad blockers
    components.adBlocker = await detectAdBlocker();
    
    return components;
}

/**
 * Generates a fingerprint using canvas rendering
 * Email scanners/bots often render canvas differently or block this
 * @returns {Promise<string>} Hash of the canvas data
 */
async function generateCanvasFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        canvas.width = 250;
        canvas.height = 60;
        const ctx = canvas.getContext('2d');
        
        // Text with different styles
        ctx.textBaseline = 'alphabetic';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        
        // Add a gradient
        const gradient = ctx.createLinearGradient(0, 0, canvas.width, 0);
        gradient.addColorStop(0, "rgba(102, 204, 0, 0.7)");
        gradient.addColorStop(1, "rgba(0, 0, 153, 0.7)");
        ctx.fillStyle = gradient;
        ctx.fillRect(0, 25, canvas.width, 35);
        
        // Draw fancy text that will be rendered differently across browsers/devices
        ctx.fillStyle = '#069';
        ctx.font = '15px Arial';
        ctx.fillText('Browser Fingerprint 👁️ Test 123', 4, 17);
        
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.font = '16px Georgia';
        ctx.fillText('I\'m a 👋 human, not a bot!', 4, 45);
        
        // Add device pixel ratio and timezone info to make it more unique
        ctx.fillStyle = 'rgba(0, 0, 0, 0.5)';
        ctx.font = '9px Arial';
        ctx.fillText(`DPR: ${window.devicePixelRatio} TZ: ${new Date().getTimezoneOffset()}`, 4, 55);
        
        // Add an emoji (renders differently across platforms)
        ctx.font = '16px Arial';
        ctx.fillText('😊', 220, 17);
        
        // Draw shapes with shadows and rotations
        ctx.shadowBlur = 7;
        ctx.shadowColor = 'rgba(0, 0, 255, 0.5)';
        ctx.beginPath();
        ctx.arc(235, 37, 10, 0, Math.PI*2);
        ctx.fill();
        
        // Capture data URL
        const dataURL = canvas.toDataURL('image/png');
        
        // Hash the data
        const encoder = new TextEncoder();
        const data = encoder.encode(dataURL);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        
        // Convert to hex
        return Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    } catch (e) {
        // Canvas might be blocked
        return "canvas_not_supported";
    }
}

/**
 * Detects installed fonts using CSS and canvas measurements
 * @returns {Array} Array of likely installed fonts
 */
function detectFonts() {
    // List of fonts to test
    const fontList = [
        'Arial', 'Arial Black', 'Arial Narrow', 'Calibri', 'Cambria', 
        'Cambria Math', 'Comic Sans MS', 'Consolas', 'Courier', 'Courier New',
        'Georgia', 'Helvetica', 'Impact', 'Lucida Console', 'Lucida Sans Unicode',
        'Microsoft Sans Serif', 'Palatino Linotype', 'Tahoma', 'Times', 
        'Times New Roman', 'Trebuchet MS', 'Verdana', 'Webdings'
    ];
    
    // Baseline fonts that should exist on any system
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    
    // Test string
    const testString = 'mmmmmmmmmmlli';
    
    // Setup test element
    const testElement = document.createElement('span');
    testElement.style.fontSize = '72px';
    testElement.innerHTML = testString;
    
    const detectedFonts = [];
    
    // Check each font
    for (const font of fontList) {
        let detected = true;
        
        // Compare with each baseline font
        for (const baseFont of baseFonts) {
            // First check with base font
            testElement.style.fontFamily = baseFont;
            document.body.appendChild(testElement);
            const baseWidth = testElement.offsetWidth;
            const baseHeight = testElement.offsetHeight;
            document.body.removeChild(testElement);
            
            // Then check with test font, falling back to base font
            testElement.style.fontFamily = `"${font}", ${baseFont}`;
            document.body.appendChild(testElement);
            const testWidth = testElement.offsetWidth;
            const testHeight = testElement.offsetHeight;
            document.body.removeChild(testElement);
            
            // If metrics are the same, font isn't installed
            if (baseWidth === testWidth && baseHeight === testHeight) {
                detected = false;
                break;
            }
        }
        
        if (detected) {
            detectedFonts.push(font);
        }
    }
    
    return detectedFonts;
}

/**
 * Gets WebGL renderer information
 * Different between devices/browsers and often faked in headless environments
 * @returns {Object} WebGL vendor and renderer info
 */
function getWebGLInfo() {
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        
        if (!gl) {
            return { vendor: null, renderer: null };
        }
        
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        
        if (!debugInfo) {
            return { vendor: null, renderer: null };
        }
        
        return {
            vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
            renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
        };
    } catch (e) {
        return { vendor: null, renderer: null };
    }
}

/**
 * Gets battery info if available
 * Often missing or fake in headless browsers
 * @returns {Promise<Object>} Battery information
 */
async function getBatteryInfo() {
    try {
        if (!navigator.getBattery) {
            return null;
        }
        
        const battery = await navigator.getBattery();
        return {
            level: battery.level,
            charging: battery.charging,
            chargingTime: battery.chargingTime,
            dischargingTime: battery.dischargingTime
        };
    } catch (e) {
        return null;
    }
}

/**
 * Gets network connection information
 * @returns {Object} Connection type and information
 */
function getConnectionType() {
    try {
        const connection = navigator.connection || 
                          navigator.mozConnection || 
                          navigator.webkitConnection;
                          
        if (!connection) {
            return null;
        }
        
        return {
            type: connection.type,
            effectiveType: connection.effectiveType,
            downlinkMax: connection.downlinkMax,
            downlink: connection.downlink,
            rtt: connection.rtt,
            saveData: connection.saveData
        };
    } catch (e) {
        return null;
    }
}

/**
 * Gets information about browser plugins
 * Often missing in headless browsers and sandboxes
 * @returns {Array} Array of plugin information
 */
function getPluginsInfo() {
    const plugins = [];
    
    try {
        if (!navigator.plugins || navigator.plugins.length === 0) {
            return plugins;
        }
        
        // Convert plugins to array and extract basic info
        for (let i = 0; i < navigator.plugins.length; i++) {
            const plugin = navigator.plugins[i];
            
            const pluginInfo = {
                name: plugin.name,
                description: plugin.description,
                filename: plugin.filename,
                mimeTypes: []
            };
            
            // Add mime types
            for (let j = 0; j < plugin.length; j++) {
                const mimeType = plugin[j];
                pluginInfo.mimeTypes.push(mimeType.type);
            }
            
            plugins.push(pluginInfo);
        }
    } catch (e) {
        // Failed to get plugins
    }
    
    return plugins;
}

/**
 * Detects supported audio codecs
 * @returns {Object} Supported audio formats
 */
function detectAudioCodecs() {
    const audio = document.createElement('audio');
    const codecs = {
        mp3: audio.canPlayType('audio/mpeg;'),
        ogg: audio.canPlayType('audio/ogg; codecs="vorbis"'),
        wav: audio.canPlayType('audio/wav; codecs="1"'),
        aac: audio.canPlayType('audio/mp4; codecs="mp4a.40.2"')
    };
    
    return codecs;
}

/**
 * Detects supported video codecs
 * @returns {Object} Supported video formats
 */
function detectVideoCodecs() {
    const video = document.createElement('video');
    const codecs = {
        h264: video.canPlayType('video/mp4; codecs="avc1.42E01E"'),
        h265: video.canPlayType('video/mp4; codecs="hev1.1.6.L93.B0"'),
        ogg: video.canPlayType('video/ogg; codecs="theora"'),
        webm: video.canPlayType('video/webm; codecs="vp8, vorbis"'),
        vp9: video.canPlayType('video/webm; codecs="vp9"')
    };
    
    return codecs;
}

/**
 * Detects if an ad blocker is present
 * @returns {Promise<boolean>} True if ad blocker detected
 */
async function detectAdBlocker() {
    return new Promise(resolve => {
        const testElement = document.createElement('div');
        testElement.innerHTML = '&nbsp;';
        testElement.className = 'adsbox pub_300x250 pub_300x250m pub_728x90 text-ad textAd text_ad';
        testElement.style.cssText = 'position: absolute; left: -10000px; top: -10000px; width: 1px; height: 1px;';
        
        document.body.appendChild(testElement);
        
        setTimeout(() => {
            let adBlockerDetected = false;
            
            if (testElement.offsetHeight === 0 || 
                testElement.clientHeight === 0 || 
                window.getComputedStyle(testElement).display === 'none' ||
                window.getComputedStyle(testElement).visibility === 'hidden') {
                adBlockerDetected = true;
            }
            
            document.body.removeChild(testElement);
            resolve(adBlockerDetected);
        }, 100);
    });
}

/**
 * Runs performance benchmarks
 * Headless browsers often show different performance characteristics
 * @returns {Object} Performance metrics
 */
function benchmarkPerformance() {
    // Start timer
    const startTime = performance.now();
    
    // Run some CPU-intensive operations
    let result = 0;
    for (let i = 0; i < 10000; i++) {
        result += Math.sqrt(i) * Math.cos(i) / (1 + Math.sin(i));
    }
    
    // Measure time
    const endTime = performance.now();
    const duration = endTime - startTime;
    
    // Create random array and sort it
    const sortStart = performance.now();
    const array = [];
    for (let i = 0; i < 5000; i++) {
        array.push(Math.random());
    }
    array.sort();
    const sortDuration = performance.now() - sortStart;
    
    return {
        mathOperationTime: duration,
        sortingTime: sortDuration,
        ratio: duration / sortDuration
    };
} 