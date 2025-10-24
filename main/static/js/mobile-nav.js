// Mobile Navigation
document.addEventListener('DOMContentLoaded', function() {
    const mobileToggle = document.querySelector('.mobile-nav-toggle');
    const nav = document.querySelector('.dashboard-nav');
    const overlay = document.querySelector('.mobile-nav-overlay');
    const navItems = document.querySelectorAll('.nav-item');

    function toggleNav() {
        nav.classList.toggle('mobile-visible');
        overlay.classList.toggle('active');
        document.body.style.overflow = nav.classList.contains('mobile-visible') ? 'hidden' : '';
        
        // Change toggle button icon
        const toggleIcon = mobileToggle.querySelector('i');
        toggleIcon.className = nav.classList.contains('mobile-visible') ? 'fas fa-times' : 'fas fa-bars';
    }

    mobileToggle.addEventListener('click', toggleNav);
    overlay.addEventListener('click', toggleNav);

    // Close nav when clicking on a link (mobile)
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            if (nav.classList.contains('mobile-visible')) {
                toggleNav();
            }
        });
    });

    // Handle window resize
    let timeout;
    window.addEventListener('resize', () => {
        clearTimeout(timeout);
        timeout = setTimeout(() => {
            if (window.innerWidth > 1024 && nav.classList.contains('mobile-visible')) {
                nav.classList.remove('mobile-visible');
                overlay.classList.remove('active');
                document.body.style.overflow = '';
            }
        }, 250);
    });
});