/**
 * Mobile Scroll Helper
 * Adds horizontal scrolling classes to product grids for mobile devices
 */

(function() {
    'use strict';
    
    // Check if mobile
    function isMobile() {
        return window.innerWidth <= 767;
    }
    
    // Add classes to product rows
    function addProductScrollClasses() {
        if (!isMobile()) return;
        
        // Find all rows with product cards
        const productRows = document.querySelectorAll('.row');
        productRows.forEach(row => {
            const hasProductCard = row.querySelector('.product-card') || 
                                  row.querySelector('[class*="product"]') ||
                                  row.id === 'productsGrid';
            
            if (hasProductCard) {
                row.classList.add('has-product-cards', 'product-row-scroll');
            }
        });
        
        // Also add to direct product grids
        const productGrids = document.querySelectorAll('#productsGrid, .products-grid');
        productGrids.forEach(grid => {
            grid.classList.add('product-row-scroll');
        });
    }
    
    // Run on page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', addProductScrollClasses);
    } else {
        addProductScrollClasses();
    }
    
    // Re-run when content is dynamically loaded
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.addedNodes.length) {
                addProductScrollClasses();
            }
        });
    });
    
    // Observe changes to main content
    const mainContent = document.querySelector('main') || document.body;
    if (mainContent) {
        observer.observe(mainContent, {
            childList: true,
            subtree: true
        });
    }
    
    // Re-run on window resize
    let resizeTimer;
    window.addEventListener('resize', function() {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(addProductScrollClasses, 250);
    });
})();

