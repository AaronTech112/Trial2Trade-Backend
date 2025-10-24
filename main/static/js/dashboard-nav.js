// Navigation Toggle Functionality
document.addEventListener('DOMContentLoaded', function() {
    const nav = document.querySelector('.dashboard-nav');
    const content = document.querySelector('.dashboard-content');
    const toggleNav = document.querySelector('.toggle-nav');
    const mobileToggle = document.querySelector('.mobile-nav-toggle');
    const navLinks = document.querySelectorAll('.nav-link span');
    const isMobile = window.innerWidth <= 768;

    // Toggle navigation
    toggleNav?.addEventListener('click', function() {
        nav.classList.toggle('collapsed');
        content.classList.toggle('expanded');
        const icon = this.querySelector('i');
        if (icon.classList.contains('fa-chevron-left')) {
            icon.classList.replace('fa-chevron-left', 'fa-chevron-right');
        } else {
            icon.classList.replace('fa-chevron-right', 'fa-chevron-left');
        }
    });

    // Mobile navigation toggle
    mobileToggle?.addEventListener('click', function() {
        nav.classList.toggle('mobile-visible');
        const icon = this.querySelector('i');
        if (icon.classList.contains('fa-bars')) {
            icon.classList.replace('fa-bars', 'fa-times');
        } else {
            icon.classList.replace('fa-times', 'fa-bars');
        }
    });

    // Close mobile nav when clicking outside
    document.addEventListener('click', function(e) {
        if (isMobile && 
            !nav.contains(e.target) && 
            !mobileToggle.contains(e.target) &&
            nav.classList.contains('mobile-visible')) {
            nav.classList.remove('mobile-visible');
            mobileToggle.querySelector('i').classList.replace('fa-times', 'fa-bars');
        }
    });

    // Handle window resize
    window.addEventListener('resize', function() {
        if (window.innerWidth > 768) {
            nav.classList.remove('mobile-visible');
            if (mobileToggle.querySelector('i').classList.contains('fa-times')) {
                mobileToggle.querySelector('i').classList.replace('fa-times', 'fa-bars');
            }
        }
    });
});

// Active page highlighting
document.addEventListener('DOMContentLoaded', function() {
    const currentPage = window.location.pathname.split('/').pop();
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPage) {
            link.classList.add('active');
        }
    });
});