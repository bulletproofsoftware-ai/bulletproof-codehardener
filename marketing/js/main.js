// Code Hardener Marketing Site JavaScript

document.addEventListener('DOMContentLoaded', function() {
  // Mobile Navigation Toggle
  const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
  const navLinks = document.querySelector('.nav-links');
  const navCta = document.querySelector('.nav-cta');

  if (mobileMenuBtn) {
    mobileMenuBtn.addEventListener('click', function() {
      navLinks.classList.toggle('active');
      navCta.classList.toggle('active');

      // Toggle hamburger animation
      const spans = this.querySelectorAll('span');
      spans.forEach(span => span.classList.toggle('active'));
    });
  }

  // Close mobile menu when clicking a link
  document.querySelectorAll('.nav-links a').forEach(link => {
    link.addEventListener('click', () => {
      navLinks.classList.remove('active');
      navCta.classList.remove('active');
    });
  });

  // Smooth scroll for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
  });

  // Navbar scroll effect
  const navbar = document.querySelector('.navbar');

  window.addEventListener('scroll', () => {
    const currentScroll = window.pageYOffset;

    if (currentScroll > 100) {
      navbar.classList.add('scrolled');
    } else {
      navbar.classList.remove('scrolled');
    }
  });

  // Animate elements on scroll
  const observerOptions = {
    root: null,
    rootMargin: '0px',
    threshold: 0.1
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('animate-in');
        observer.unobserve(entry.target);
      }
    });
  }, observerOptions);

  // Observe all animatable elements
  document.querySelectorAll('.feature-card, .integration-item, .pricing-card, .testimonial-card, .step').forEach(el => {
    el.classList.add('animate-target');
    observer.observe(el);
  });

  // Pricing toggle (monthly/annual)
  const pricingToggle = document.querySelector('.pricing-toggle');
  if (pricingToggle) {
    pricingToggle.addEventListener('click', function() {
      this.classList.toggle('annual');
      updatePrices();
    });
  }

  function updatePrices() {
    const isAnnual = pricingToggle?.classList.contains('annual');
    const prices = {
      pro: { monthly: 19, annual: 15 },
      team: { monthly: 39, annual: 31 }
    };

    document.querySelectorAll('[data-price]').forEach(el => {
      const plan = el.dataset.price;
      if (prices[plan]) {
        el.textContent = isAnnual ? prices[plan].annual : prices[plan].monthly;
      }
    });

    document.querySelectorAll('.billing-period').forEach(el => {
      el.textContent = isAnnual ? '/month, billed annually' : '/month';
    });
  }

  // Helper function to create SVG icon
  function createCopyIcon() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '16');
    svg.setAttribute('height', '16');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');

    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    rect.setAttribute('x', '9');
    rect.setAttribute('y', '9');
    rect.setAttribute('width', '13');
    rect.setAttribute('height', '13');
    rect.setAttribute('rx', '2');
    rect.setAttribute('ry', '2');

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1');

    svg.appendChild(rect);
    svg.appendChild(path);
    return svg;
  }

  function createCheckIcon() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '16');
    svg.setAttribute('height', '16');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');

    const polyline = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
    polyline.setAttribute('points', '20 6 9 17 4 12');

    svg.appendChild(polyline);
    return svg;
  }

  // Copy code snippets
  document.querySelectorAll('.code-block').forEach(block => {
    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.appendChild(createCopyIcon());

    copyBtn.addEventListener('click', async () => {
      const code = block.querySelector('code').textContent;
      await navigator.clipboard.writeText(code);

      // Clear and add check icon
      while (copyBtn.firstChild) {
        copyBtn.removeChild(copyBtn.firstChild);
      }
      copyBtn.appendChild(createCheckIcon());

      setTimeout(() => {
        while (copyBtn.firstChild) {
          copyBtn.removeChild(copyBtn.firstChild);
        }
        copyBtn.appendChild(createCopyIcon());
      }, 2000);
    });

    block.appendChild(copyBtn);
  });

  // Form validation
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    form.addEventListener('submit', function(e) {
      e.preventDefault();

      const email = this.querySelector('input[type="email"]');
      if (email && !isValidEmail(email.value)) {
        showError(email, 'Please enter a valid email address');
        return;
      }

      // Show success message
      showSuccess(this);
    });
  });

  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  function showError(input, message) {
    const error = document.createElement('div');
    error.className = 'error-message';
    error.textContent = message;
    input.parentNode.appendChild(error);
    input.classList.add('error');

    setTimeout(() => {
      error.remove();
      input.classList.remove('error');
    }, 3000);
  }

  function showSuccess(form) {
    const success = document.createElement('div');
    success.className = 'success-message';
    success.textContent = 'Thanks! We\'ll be in touch soon.';
    form.appendChild(success);
    form.reset();

    setTimeout(() => success.remove(), 5000);
  }

  // Stats counter animation
  const stats = document.querySelectorAll('.stat-number');
  const statsObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        animateValue(entry.target);
        statsObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.5 });

  stats.forEach(stat => statsObserver.observe(stat));

  function animateValue(el) {
    const target = parseInt(el.dataset.value || el.textContent, 10);
    const duration = 2000;
    const start = 0;
    const startTime = performance.now();

    function update(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = Math.floor(start + (target - start) * eased);

      el.textContent = current.toLocaleString() + (el.dataset.suffix || '');

      if (progress < 1) {
        requestAnimationFrame(update);
      }
    }

    requestAnimationFrame(update);
  }

  // Testimonial carousel (if needed)
  const testimonialContainer = document.querySelector('.testimonials-grid');
  if (testimonialContainer && window.innerWidth < 768) {
    let currentSlide = 0;
    const slides = testimonialContainer.querySelectorAll('.testimonial-card');
    const totalSlides = slides.length;

    function showSlide(index) {
      slides.forEach((slide, i) => {
        slide.style.display = i === index ? 'block' : 'none';
      });
    }

    // Auto-advance slides on mobile
    setInterval(() => {
      currentSlide = (currentSlide + 1) % totalSlides;
      showSlide(currentSlide);
    }, 5000);
  }

  // Keyboard navigation for accessibility
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      navLinks.classList.remove('active');
      navCta.classList.remove('active');
    }
  });

  console.log('Code Hardener marketing site loaded');
});
