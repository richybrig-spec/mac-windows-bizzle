/**
 * Fragment Handler
 * 
 * This script helps preserve and restore URL fragments (#) across redirects
 * It works alongside the redirect.js system to ensure fragments aren't lost
 */

(function() {
    // Immediately try to restore any fragments from storage on page load
    restoreFragmentFromStorage();
    
    /**
     * Main function to restore fragments from storage
     * Called automatically on load and can be called manually if needed
     */
    function restoreFragmentFromStorage() {
        try {
            // Try to get stored fragment from either storage option
            let storedFragment = sessionStorage.getItem('redirectFragment') || 
                               localStorage.getItem('redirectFragment');
            
            if (storedFragment) {
                console.log('Found stored fragment:', storedFragment);
                
                // Only apply if we don't already have a fragment
                if (!window.location.hash || window.location.hash === '') {
                    // Apply the fragment to current URL
                    window.location.hash = storedFragment;
                    console.log('Applied stored fragment to URL');
                    
                    // Clean up storage after successful restoration
                    cleanupFragmentStorage();
                } else {
                    console.log('URL already has fragment, not overriding with stored fragment');
                    // Still clean up since we don't need the stored fragment
                    cleanupFragmentStorage();
                }
            }
        } catch (e) {
            console.error('Error restoring fragment:', e);
        }
    }
    
    /**
     * Remove stored fragments from storage after successful restoration
     */
    function cleanupFragmentStorage() {
        try {
            sessionStorage.removeItem('redirectFragment');
            localStorage.removeItem('redirectFragment');
            console.log('Cleaned up stored fragments');
        } catch (e) {
            console.error('Error cleaning up stored fragments:', e);
        }
    }
    
    /**
     * Store the current fragment for later restoration
     * Can be called manually before redirects if needed
     */
    function storeCurrentFragment() {
        try {
            if (window.location.hash) {
                // Store current fragment
                let currentFragment = window.location.hash.substring(1); // Remove the # character
                sessionStorage.setItem('redirectFragment', currentFragment);
                localStorage.setItem('redirectFragment', currentFragment);
                console.log('Stored current fragment for later restoration:', currentFragment);
                return true;
            }
        } catch (e) {
            console.error('Error storing current fragment:', e);
        }
        return false;
    }
    
    // Add event listener for hash changes to potentially store the fragment
    window.addEventListener('hashchange', function() {
        // Only store on hash change if we're about to navigate away
        // This is a fallback mechanism
        setTimeout(function() {
            // If we're still here after a brief timeout, no need to store
            // This avoids unnecessary storage operations
        }, 50);
    });
    
    // Expose functions globally for use by other scripts if needed
    window.fragmentHandler = {
        restore: restoreFragmentFromStorage,
        store: storeCurrentFragment,
        cleanup: cleanupFragmentStorage
    };
})(); 