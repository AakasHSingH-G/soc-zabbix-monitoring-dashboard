/* ==================== NAVBAR EFFECTS ==================== */
const navbar = document.getElementById('navbar');

window.addEventListener('scroll', () => {
    if (window.scrollY > 100) {
        navbar.classList.add('scrolled');
    } else {
        navbar.classList.remove('scrolled');
    }
});

/* ==================== STATS COUNTER ANIMATION ==================== */
const animateCounters = () => {
    const counters = document.querySelectorAll('.counter');
    const speed = 150;

    counters.forEach(counter => {
        if (counter.classList.contains('animated')) return;
        
        const target = +counter.getAttribute('data-target');
        const updateCount = () => {
            const count = +counter.innerText;
            const increment = target / speed;

            if (count < target) {
                counter.innerText = Math.ceil(count + increment);
                setTimeout(updateCount, 10);
            } else {
                counter.innerText = target.toLocaleString() + (counter.getAttribute('data-suffix') || '');
                counter.classList.add('animated');
            }
        };
        updateCount();
    });
};

/* ==================== REVEAL ON SCROLL ==================== */
const reveal = () => {
    const reveals = document.querySelectorAll('.reveal');
    const windowHeight = window.innerHeight;
    const revealPoint = 100;
    
    reveals.forEach(element => {
        const revealTop = element.getBoundingClientRect().top;
        
        if (revealTop < windowHeight - revealPoint) {
            element.classList.add('active');
            
            // Trigger counter animation if stats section is revealed
            if (element.classList.contains('stats-grid-row')) {
                animateCounters();
            }

            // Trigger terminal animation if terminal section is revealed
            if (element.id === 'terminal-trigger') {
                startTerminal();
            }
        }
    });
}

window.addEventListener('scroll', reveal);
document.addEventListener('DOMContentLoaded', reveal);

/* ==================== SMOOTH SCROLLING ==================== */
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();

        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            const headerOffset = 90;
            const elementPosition = target.getBoundingClientRect().top;
            const offsetPosition = elementPosition + window.scrollY - headerOffset;

            window.scrollTo({
                top: offsetPosition,
                behavior: "smooth"
            });
        }
    });
});

/* ==================== SECURITY CARD INTERACTION ==================== */
const securityCards = document.querySelectorAll('.security-card, .data-card');

securityCards.forEach(card => {
    card.addEventListener('mouseenter', () => {
        const icon = card.querySelector('i, .feature-icon');
        if (icon) {
            icon.style.transform = 'scale(1.25) rotate(10deg)';
            icon.style.filter = 'drop-shadow(0 0 15px var(--accent-cyan))';
        }
    });

    card.addEventListener('mouseleave', () => {
        const icon = card.querySelector('i, .feature-icon');
        if (icon) {
            icon.style.transform = 'scale(1) rotate(0deg)';
            icon.style.filter = 'none';
        }
    });
});

/* ==================== PARALLAX MOCKUP ==================== */
window.addEventListener('scroll', () => {
    const mockup = document.querySelector('.hero-mockup img');
    if (mockup) {
        const scrolled = window.scrollY;
        mockup.style.transform = `translateY(${scrolled * -0.05}px)`;
    }
});

/* ==================== AUTOMATION FLOWCHART ANIMATOR ==================== */
const animateFlowchart = () => {
    const nodes = [
        document.querySelector('.node-trigger'),
        document.querySelector('.node-engine'),
        ...document.querySelectorAll('.node-action')
    ];
    
    nodes.forEach((node, index) => {
        if (node) {
            setTimeout(() => {
                node.style.borderColor = 'var(--accent-cyan)';
                node.style.boxShadow = '0 0 30px rgba(0, 255, 255, 0.3)';
                node.style.transform = 'translateY(-10px) scale(1.05)';
                
                setTimeout(() => {
                    node.style.borderColor = 'var(--glass-border)';
                    node.style.boxShadow = 'none';
                    node.style.transform = 'translateY(0) scale(1)';
                }, 1000);
            }, index * 800);
        }
    });

    // Loop the sequential animation
    setTimeout(animateFlowchart, nodes.length * 800 + 4000);
};

// Start flowchart animation when it enters the viewport
const flowchartObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            animateFlowchart();
            flowchartObserver.unobserve(entry.target);
        }
    });
}, { threshold: 0.5 });

const automationSection = document.getElementById('automation');
if (automationSection) {
    flowchartObserver.observe(automationSection);
}


/* ==================== TERMINAL SIMULATOR ==================== */
const terminalLines = [
    { text: '> Initializing Zabbix Stealth Installer v3.0...', type: 'info' },
    { text: '> Checking system architecture... x64 detected.', type: 'info' },
    { text: '> Verifying kernel permissions... OK', type: 'info' },
    { text: '> Securing environment variables...', type: 'warning' },
    { text: '> Deploying core background service...', type: 'info' },
    { text: '> Setting up E2EE WebSocket tunnels...', type: 'info' },
    { text: '> Injecting monitoring payload [process: stealth]...', type: 'warning' },
    { text: '> Payload successfully hidden from task scheduler.', type: 'success' },
    { text: '> Optimizing system performance (RAM/CPU)... Done', type: 'success' },
    { text: '> Deployment Status: 100% SUCCESSFUL', type: 'success' },
    { text: '> Zabbix Stealth is now running in the background.', type: 'info' },
    { text: '> Shutting down console to maintain stealth.', type: 'warning' }
];

let terminalStarted = false;
const startTerminal = () => {
    if (terminalStarted) return;
    terminalStarted = true;
    
    const terminalBody = document.getElementById('terminal-body');
    if (!terminalBody) return;
    
    let index = 0;
    const typeLine = () => {
        if (index < terminalLines.length) {
            const lineData = terminalLines[index];
            const lineDiv = document.createElement('div');
            lineDiv.className = 'line ' + lineData.type;
            lineDiv.innerHTML = lineData.text;
            terminalBody.appendChild(lineDiv);
            
            setTimeout(() => lineDiv.classList.add('active'), 50);
            
            terminalBody.scrollTop = terminalBody.scrollHeight;
            index++;
            setTimeout(typeLine, Math.random() * 500 + 400);
        }
    };
    typeLine();
};


