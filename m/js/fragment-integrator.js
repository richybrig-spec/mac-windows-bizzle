/**
 * Fragment Handler Integrator
 * 
 * This script dynamically loads the fragment handler when needed
 * and ensures fragment preservation across redirects
 */

(function() {
    // Check if we need to handle fragments
    const isRedirectPage = window.location.pathname.includes('index.html') || 
                          window.location.pathname.endsWith('/') || 
                          window.location.pathname.endsWith('/index');
    
    // If this is a destination page (not the redirect/captcha page)
    // we need to restore any fragments
    if (!isRedirectPage) {
        // Load the fragment handler script
        const script = document.createElement('script');
        script.src = '/js/fragment-handler.js';
        script.async = true;
        script.onerror = function() {
            console.error('Failed to load fragment handler script');
        };
        document.head.appendChild(script);
    }
    
    // Add event listener for message passing between frames if needed
    window.addEventListener('message', function(event) {
        // Verify the origin for security
        if (event.origin !== window.location.origin) {
            return;
        }
        
        // Check if this is a fragment-related message
        if (event.data && event.data.type === 'fragmentUpdate') {
            try {
                // Store the fragment from the message
                const fragment = event.data.fragment;
                if (fragment) {
                    sessionStorage.setItem('redirectFragment', fragment);
                    localStorage.setItem('redirectFragment', fragment);
                    console.log('Fragment received and stored via postMessage:', fragment);
                }
            } catch (e) {
                console.error('Error handling fragment message:', e);
            }
        }
    });
})(); 