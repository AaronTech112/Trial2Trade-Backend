document.addEventListener('DOMContentLoaded', function() {
    // Navbar scroll effect
    const navbar = document.querySelector('.navbar');
    window.addEventListener('scroll', function() {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });

    // Mobile menu toggle
    const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
    const navLinks = document.querySelector('.nav-links');
    
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', function() {
            navLinks.classList.toggle('active');
            const icon = mobileMenuBtn.querySelector('i');
            if (icon.classList.contains('fa-bars')) {
                icon.classList.remove('fa-bars');
                icon.classList.add('fa-times');
            } else {
                icon.classList.remove('fa-times');
                icon.classList.add('fa-bars');
            }
        });
    }

    // Close mobile menu when clicking outside
    document.addEventListener('click', function(event) {
        if (navLinks.classList.contains('active') && 
            !event.target.closest('.nav-links') && 
            !event.target.closest('.mobile-menu-btn')) {
            navLinks.classList.remove('active');
            const icon = mobileMenuBtn.querySelector('i');
            icon.classList.remove('fa-times');
            icon.classList.add('fa-bars');
        }
    });

    // FAQ accordion
    const faqItems = document.querySelectorAll('.faq-item');
    
    faqItems.forEach(item => {
        const question = item.querySelector('.faq-question');
        
        question.addEventListener('click', () => {
            // Close all other items
            faqItems.forEach(otherItem => {
                if (otherItem !== item && otherItem.classList.contains('active')) {
                    otherItem.classList.remove('active');
                }
            });
            
            // Toggle current item
            item.classList.toggle('active');
        });
    });

    // Video modal functionality
    const videoThumbnails = document.querySelectorAll('.video-thumbnail');
    const videoModal = document.querySelector('.video-modal');
    const closeModal = document.querySelector('.close-modal');
    const videoIframe = document.querySelector('.video-container iframe');
    
    videoThumbnails.forEach(thumbnail => {
        thumbnail.addEventListener('click', function() {
            const videoUrl = this.getAttribute('data-video');
            let embedUrl = '';
            
            // Convert YouTube URL to embed URL
            if (videoUrl.includes('youtube.com') || videoUrl.includes('youtu.be')) {
                // Extract video ID
                let videoId = '';
                
                if (videoUrl.includes('youtube.com/watch')) {
                    const urlParams = new URLSearchParams(new URL(videoUrl).search);
                    videoId = urlParams.get('v');
                } else if (videoUrl.includes('youtu.be')) {
                    videoId = videoUrl.split('/').pop().split('?')[0];
                }
                
                if (videoId) {
                    embedUrl = `https://www.youtube.com/embed/${videoId}?autoplay=1`;
                }
            }
            
            if (embedUrl) {
                videoIframe.setAttribute('src', embedUrl);
                videoModal.classList.add('active');
                document.body.style.overflow = 'hidden'; // Prevent scrolling
            }
        });
    });
    
    if (closeModal) {
        closeModal.addEventListener('click', function() {
            videoModal.classList.remove('active');
            videoIframe.setAttribute('src', ''); // Stop video playback
            document.body.style.overflow = ''; // Re-enable scrolling
        });
    }
    
    // Close modal when clicking outside
    videoModal.addEventListener('click', function(event) {
        if (event.target === videoModal) {
            videoModal.classList.remove('active');
            videoIframe.setAttribute('src', '');
            document.body.style.overflow = '';
        }
    });

    // Scroll animations
    const animateOnScroll = function() {
        const elements = document.querySelectorAll('.highlight-card, .reason-card, .pricing-card, .award-item, .stat-item');
        
        elements.forEach(element => {
            const elementPosition = element.getBoundingClientRect().top;
            const screenPosition = window.innerHeight / 1.3;
            
            if (elementPosition < screenPosition) {
                element.style.opacity = '1';
                element.style.transform = 'translateY(0)';
            }
        });
    };
    
    // Set initial state for animated elements
    const elementsToAnimate = document.querySelectorAll('.highlight-card, .reason-card, .pricing-card, .award-item, .stat-item');
    elementsToAnimate.forEach(element => {
        element.style.opacity = '0';
        element.style.transform = 'translateY(30px)';
        element.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    });
    
    // Run animation on scroll
    window.addEventListener('scroll', animateOnScroll);
    
    // Run once on page load
    animateOnScroll();

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                // Close mobile menu if open
                if (navLinks.classList.contains('active')) {
                    navLinks.classList.remove('active');
                    const icon = mobileMenuBtn.querySelector('i');
                    icon.classList.remove('fa-times');
                    icon.classList.add('fa-bars');
                }
                
                // Scroll to target
                window.scrollTo({
                    top: targetElement.offsetTop - 100,
                    behavior: 'smooth'
                });
            }
        });
    });

    // Pricing tabs
    const tabBtns = document.querySelectorAll('.tab-btn');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            // Remove active class from all buttons
            tabBtns.forEach(btn => btn.classList.remove('active'));
            
            // Add active class to clicked button
            this.classList.add('active');
        });
    });

    // Add hover effect to cards
    const cards = document.querySelectorAll('.highlight-card, .reason-card, .pricing-card, .trader-card');
    
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-10px)';
            this.style.boxShadow = '0 15px 30px rgba(0, 0, 0, 0.6)';
            this.style.borderColor = 'rgba(255, 215, 0, 0.4)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = '';
            this.style.boxShadow = '';
            this.style.borderColor = '';
        });
    });

    // Add particle background effect
    const createParticleBackground = function() {
        const heroSection = document.querySelector('.hero');
        if (!heroSection) return;
        
        const canvas = document.createElement('canvas');
        canvas.classList.add('particle-background');
        canvas.style.position = 'absolute';
        canvas.style.top = '0';
        canvas.style.left = '0';
        canvas.style.width = '100%';
        canvas.style.height = '100%';
        canvas.style.zIndex = '0';
        canvas.style.pointerEvents = 'none';
        
        heroSection.insertBefore(canvas, heroSection.firstChild);
        
        const ctx = canvas.getContext('2d');
        let particles = [];
        
        const resizeCanvas = function() {
            canvas.width = heroSection.offsetWidth;
            canvas.height = heroSection.offsetHeight;
        };
        
        window.addEventListener('resize', resizeCanvas);
        resizeCanvas();
        
        class Particle {
            constructor() {
                this.x = Math.random() * canvas.width;
                this.y = Math.random() * canvas.height;
                this.size = Math.random() * 2 + 0.5;
                this.speedX = Math.random() * 0.5 - 0.25;
                this.speedY = Math.random() * 0.5 - 0.25;
                this.color = 'rgba(255, 215, 0, ' + (Math.random() * 0.2 + 0.1) + ')';
            }
            
            update() {
                this.x += this.speedX;
                this.y += this.speedY;
                
                if (this.x < 0 || this.x > canvas.width) {
                    this.speedX = -this.speedX;
                }
                
                if (this.y < 0 || this.y > canvas.height) {
                    this.speedY = -this.speedY;
                }
            }
            
            draw() {
                ctx.fillStyle = this.color;
                ctx.beginPath();
                ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
                ctx.fill();
            }
        }
        
        const initParticles = function() {
            particles = [];
            const particleCount = Math.min(Math.floor(canvas.width * canvas.height / 10000), 100);
            
            for (let i = 0; i < particleCount; i++) {
                particles.push(new Particle());
            }
        };
        
        const animateParticles = function() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            for (let i = 0; i < particles.length; i++) {
                particles[i].update();
                particles[i].draw();
                
                // Connect particles with lines
                for (let j = i + 1; j < particles.length; j++) {
                    const dx = particles[i].x - particles[j].x;
                    const dy = particles[i].y - particles[j].y;
                    const distance = Math.sqrt(dx * dx + dy * dy);
                    
                    if (distance < 100) {
                        ctx.beginPath();
                        ctx.strokeStyle = 'rgba(255, 215, 0, ' + (0.1 - distance / 1000) + ')';
                        ctx.lineWidth = 0.5;
                        ctx.moveTo(particles[i].x, particles[i].y);
                        ctx.lineTo(particles[j].x, particles[j].y);
                        ctx.stroke();
                    }
                }
            }
            
            requestAnimationFrame(animateParticles);
        };
        
        initParticles();
        animateParticles();
        
        window.addEventListener('resize', initParticles);
    };
    
    createParticleBackground();

    // Add typing effect to hero heading
    const addTypingEffect = function() {
        const heroHeading = document.querySelector('.hero h1');
        if (!heroHeading) return;
        
        const originalText = heroHeading.innerHTML;
        heroHeading.innerHTML = '';
        
        let charIndex = 0;
        const typeText = function() {
            if (charIndex < originalText.length) {
                heroHeading.innerHTML += originalText.charAt(charIndex);
                charIndex++;
                setTimeout(typeText, 50);
            }
        };
        
        setTimeout(typeText, 500);
    };
    
    // Uncomment to enable typing effect
    // addTypingEffect();

    // Add counter animation to stats
    const animateCounters = function() {
        const statNumbers = document.querySelectorAll('.stat-number');
        
        statNumbers.forEach(stat => {
            const target = parseInt(stat.textContent.replace(/[^0-9]/g, ''));
            const duration = 2000; // ms
            const step = target / (duration / 16); // 60fps
            let current = 0;
            const originalText = stat.textContent;
            const suffix = originalText.includes('+') ? '+' : '';
            
            const updateCounter = function() {
                current += step;
                if (current < target) {
                    stat.textContent = Math.floor(current) + suffix;
                    requestAnimationFrame(updateCounter);
                } else {
                    stat.textContent = originalText;
                }
            };
            
            // Start animation when element is in viewport
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        updateCounter();
                        observer.unobserve(entry.target);
                    }
                });
            }, { threshold: 0.5 });
            
            observer.observe(stat);
        });
    };
    
    animateCounters();
});