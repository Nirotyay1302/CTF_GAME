// Enhanced Dashboard JavaScript
class DashboardEnhanced {
    constructor() {
        this.socket = null;
        this.leaderboardData = {
            individual: [],
            teams: []
        };
        this.filters = {
            search: '',
            difficulty: '',
            category: '',
            status: ''
        };
        this.tournamentTimer = null;
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupWebSocket();
        this.setupFilters();
        this.setupLeaderboard();
        this.setupTournamentTimer();
        this.setupChallengeTimers();
        this.setupMobileOptimization();
        this.maybeShowOnboarding();
        this.setupNotifications();
        this.setupNotificationSidebar();
    }

    // Event Listeners
    setupEventListeners() {
        // Theme toggle is now handled by the global theme manager

        // Search functionality
        const searchInput = document.getElementById('challengeSearch');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.filters.search = e.target.value.toLowerCase();
                this.applyFilters();
            });
        }

        // Filter selects
        const filterSelects = ['difficultyFilter', 'categoryFilter', 'statusFilter'];
        filterSelects.forEach(filterId => {
            const select = document.getElementById(filterId);
            if (select) {
                select.addEventListener('change', (e) => {
                    this.filters[filterId.replace('Filter', '')] = e.target.value;
                    this.applyFilters();
                });
            }
        });

        // Leaderboard sidebar toggle
        const sidebarToggle = document.getElementById('sidebarToggle');
        if (sidebarToggle) {
            sidebarToggle.addEventListener('click', () => this.toggleLeaderboardSidebar());
        }

        // Tab switching
        const tabButtons = document.querySelectorAll('.tab-btn');
        tabButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
            });
        });

        // Form submissions with enhanced UX
        this.setupFormEnhancements();
    }

    setupFormEnhancements() {
        // Flag submission with AJAX and loading states
        const flagForms = document.querySelectorAll('.flag-form');
        flagForms.forEach(form => {
            const input = form.querySelector('input[name="flag"]');
            const submitBtn = form.querySelector('.flag-submit') || form.querySelector('button[type="submit"]');
            const cardEl = form.closest('.challenge-card') || form.closest('.challenge-item');

            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                if (!input || !input.value.trim()) return;

                const originalHTML = submitBtn ? submitBtn.innerHTML : '';
                if (submitBtn) {
                    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
                    submitBtn.disabled = true;
                }

                try {
                    const action = form.getAttribute('action') || '';
                    const match = action.match(/\/submit\/(\d+)/);
                    const challengeId = match ? match[1] : null;
                    if (!challengeId) throw new Error('Missing challenge id');

                    const resp = await fetch(`/api/submit_flag/${challengeId}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ flag: input.value.trim() })
                    });
                    const data = await resp.json();

                    if (!resp.ok || !data.success) {
                        const msg = (data && (data.error || data.message)) || 'Submission failed';
                        this.showNotification(msg, 'error');
                    } else if (data.correct) {
                        this.showNotification(data.message || 'Correct!', 'success');
                        if (typeof data.new_score === 'number') {
                            this.updateUserScore(data.new_score);
                        }
                        // Mark as solved and remove form
                        if (cardEl) {
                            const solvedBadge = cardEl.querySelector('.badge.solved');
                            if (solvedBadge) solvedBadge.style.display = 'inline-flex';
                            const solvedDiv = cardEl.querySelector('.challenge-solved');
                            if (solvedDiv) solvedDiv.style.display = 'flex';
                        }
                        form.remove();
                    } else {
                        this.showNotification(data.message || 'Incorrect flag', 'error');
                    }
                } catch (err) {
                    console.error('Submit error', err);
                    this.showNotification('Submission error', 'error');
                } finally {
                    if (submitBtn) {
                        submitBtn.innerHTML = originalHTML || 'Submit';
                        submitBtn.disabled = false;
                    }
                }
            });
        });
    }

    // WebSocket Setup
    setupWebSocket() {
        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Connected to server');
            this.socket.emit('join_tournament');
            this.socket.emit('join_leaderboard');
        });

        this.socket.on('disconnect', () => {
            console.log('Disconnected from server');
        });

        this.socket.on('leaderboard_update', (data) => {
            this.updateLeaderboard(data);
        });

        this.socket.on('tournament_timer', (data) => {
            this.updateTournamentTimer(data);
        });

        this.socket.on('tournament_ended', (data) => {
            this.handleTournamentEnd(data);
        });

        this.socket.on('score_update', (data) => {
            this.updateUserScore(data.score);
        });
    }

    // Filtering and Search
    setupFilters() {
        this.applyFilters();
    }

    applyFilters() {
        const challengeCards = document.querySelectorAll('.challenge-card');
        let visibleCount = 0;

        challengeCards.forEach(card => {
            const title = card.querySelector('h3').textContent.toLowerCase();
            const difficulty = card.dataset.difficulty;
            const category = card.dataset.category;
            const solved = card.dataset.solved;

            let shouldShow = true;

            // Search filter
            if (this.filters.search && !title.includes(this.filters.search)) {
                shouldShow = false;
            }

            // Difficulty filter
            if (this.filters.difficulty && difficulty !== this.filters.difficulty) {
                shouldShow = false;
            }

            // Category filter
            if (this.filters.category && category !== this.filters.category) {
                shouldShow = false;
            }

            // Status filter
            if (this.filters.status) {
                if (this.filters.status === 'solved' && solved !== 'true') {
                    shouldShow = false;
                } else if (this.filters.status === 'unsolved' && solved !== 'false') {
                    shouldShow = false;
                }
            }

            if (shouldShow) {
                card.style.display = 'block';
                visibleCount++;
            } else {
                card.style.display = 'none';
            }
        });

        // Update challenge count
        const challengeCount = document.getElementById('challengeCount');
        if (challengeCount) {
            challengeCount.textContent = visibleCount;
        }

        // Show/hide empty state
        const noChallenges = document.getElementById('noChallenges');
        if (noChallenges) {
            if (visibleCount === 0) {
                noChallenges.style.display = 'block';
            } else {
                noChallenges.style.display = 'none';
            }
        }
    }

    // Leaderboard Management
    setupLeaderboard() {
        // Initialize with empty state
        this.updateLeaderboardDisplay();
        
        // Auto-refresh leaderboard every 30 seconds
        setInterval(() => {
            this.fetchLeaderboardData();
        }, 30000);

        // Setup filter controls
        const lbCategory = document.getElementById('lbCategory');
        const lbWindow = document.getElementById('lbWindow');
        if (lbCategory) lbCategory.addEventListener('change', () => this.fetchLeaderboardData());
        if (lbWindow) lbWindow.addEventListener('change', () => this.fetchLeaderboardData());
    }

    async fetchLeaderboardData() {
        try {
            const lbCategory = document.getElementById('lbCategory');
            const lbWindow = document.getElementById('lbWindow');
            const cat = lbCategory ? lbCategory.value : '';
            const win = lbWindow ? lbWindow.value : '';
            const qs = new URLSearchParams({ category: cat, window: win }).toString();

            const [individualResponse, teamsResponse] = await Promise.all([
                fetch('/api/leaderboard/individual?' + qs),
                fetch('/api/leaderboard/teams?' + qs)
            ]);

            if (individualResponse.ok) {
                const individualData = await individualResponse.json();
                this.leaderboardData.individual = individualData;
            }

            if (teamsResponse.ok) {
                const teamsData = await teamsResponse.json();
                this.leaderboardData.teams = teamsData;
            }

            this.updateLeaderboardDisplay();
        } catch (error) {
            console.error('Error fetching leaderboard data:', error);
        }
    }

    updateLeaderboard(data) {
        if (data.type === 'individual') {
            this.leaderboardData.individual = data.players;
        } else if (data.type === 'teams') {
            this.leaderboardData.teams = data.teams;
        }
        
        this.updateLeaderboardDisplay();
    }

    updateLeaderboardDisplay() {
        this.updateIndividualLeaderboard();
        this.updateTeamsLeaderboard();
    }

    updateIndividualLeaderboard() {
        const container = document.getElementById('individualLeaderboard');
        if (!container) return;

        const currentUser = this.getCurrentUsername();
        
        container.innerHTML = this.leaderboardData.individual
            .slice(0, 10) // Show top 10
            .map((player, index) => {
                const isCurrentUser = player.username === currentUser;
                const rankClass = index < 3 ? `rank-${index + 1}` : '';
                
                return `
                    <div class="leaderboard-item ${isCurrentUser ? 'current-user' : ''}">
                        <div class="leaderboard-rank ${rankClass}">${index + 1}</div>
                        <div class="leaderboard-info">
                            <div class="leaderboard-name">${player.username}</div>
                            <div class="leaderboard-score">${player.score} points</div>
                        </div>
                    </div>
                `;
            })
            .join('');
    }

    updateTeamsLeaderboard() {
        const container = document.getElementById('teamsLeaderboard');
        if (!container) return;

        container.innerHTML = this.leaderboardData.teams
            .slice(0, 10) // Show top 10
            .map((team, index) => {
                const rankClass = index < 3 ? `rank-${index + 1}` : '';
                
                return `
                    <div class="leaderboard-item">
                        <div class="leaderboard-rank ${rankClass}">${index + 1}</div>
                        <div class="leaderboard-info">
                            <div class="leaderboard-name">${team.name}</div>
                            <div class="leaderboard-score">${team.score} points • ${team.members} members</div>
                        </div>
                    </div>
                `;
            })
            .join('');
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${tabName}Tab`).classList.add('active');
    }

    toggleLeaderboardSidebar() {
        const sidebar = document.getElementById('leaderboardSidebar');
        const mainContent = document.querySelector('.main-content');
        const toggleBtn = document.getElementById('sidebarToggle');
        
        if (sidebar.classList.contains('open')) {
            sidebar.classList.remove('open');
            mainContent.classList.remove('sidebar-open');
            toggleBtn.innerHTML = '<i class="fas fa-chevron-left"></i>';
        } else {
            sidebar.classList.add('open');
            mainContent.classList.add('sidebar-open');
            toggleBtn.innerHTML = '<i class="fas fa-chevron-right"></i>';
        }
    }

    // Tournament Timer
    setupTournamentTimer() {
        const timerElement = document.getElementById('time-remaining');
        const progressBar = document.getElementById('timer-progress-bar');
        
        if (!timerElement) return;

        // Fetch initial tournament status
        this.fetchTournamentStatus();
    }

    // Per-challenge countdown timers
    setupChallengeTimers() {
        const timers = document.querySelectorAll('.challenge-card .timer, .challenge-item .timer');
        timers.forEach(timer => {
            const endIso = timer.getAttribute('data-end');
            if (!endIso) return;
            const label = timer.querySelector('.time-left');
            const interval = setInterval(() => {
                const now = Date.now();
                const end = new Date(endIso).getTime();
                const diff = end - now;
                if (diff <= 0) {
                    clearInterval(interval);
                    label.textContent = 'Closed';
                    const card = timer.closest('.challenge-card') || timer.closest('.challenge-item');
                    if (card) {
                        const form = card.querySelector('.flag-form');
                        if (form) form.remove();
                    }
                    return;
                }
                const h = Math.floor(diff / 3600000);
                const m = Math.floor((diff % 3600000) / 60000);
                const s = Math.floor((diff % 60000) / 1000);
                label.textContent = `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
            }, 1000);
        });
    }

    async fetchTournamentStatus() {
        try {
            const response = await fetch('/tournament/status');
            if (response.ok) {
                const data = await response.json();
                if (data.active) {
                    this.startTournamentTimer(data.end_time);
                }
            }
        } catch (error) {
            console.error('Error fetching tournament status:', error);
        }
    }

    startTournamentTimer(endTime) {
        if (this.tournamentTimer) {
            clearInterval(this.tournamentTimer);
        }

        this.tournamentTimer = setInterval(() => {
            this.updateTournamentTimer({ end_time: endTime });
        }, 1000);
    }

    updateTournamentTimer(data) {
        const timerElement = document.getElementById('time-remaining');
        const progressBar = document.getElementById('timer-progress-bar');
        
        if (!timerElement) return;

        const now = new Date().getTime();
        const end = new Date(data.end_time).getTime();
        const timeLeft = end - now;
        const totalTime = end - new Date(data.start_time || now - 3600000).getTime();

        if (timeLeft <= 0) {
            timerElement.innerHTML = 'Tournament Ended!';
            if (progressBar) progressBar.style.width = '0%';
            clearInterval(this.tournamentTimer);
            return;
        }

        // Update timer display
        const days = Math.floor(timeLeft / (1000 * 60 * 60 * 24));
        const hours = Math.floor((timeLeft % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);

        let timeString = '';
        if (days > 0) timeString += `${days}d `;
        if (hours > 0) timeString += `${hours}h `;
        if (minutes > 0) timeString += `${minutes}m `;
        timeString += `${seconds}s`;

        timerElement.innerHTML = timeString;

        // Update progress bar
        if (progressBar) {
            const progressPercent = Math.max(0, (timeLeft / totalTime) * 100);
            progressBar.style.width = `${progressPercent}%`;
        }

        // Color coding for urgency
        if (timeLeft < 300000) { // Less than 5 minutes
            timerElement.style.color = '#ef4444';
            timerElement.style.fontWeight = 'bold';
        } else if (timeLeft < 900000) { // Less than 15 minutes
            timerElement.style.color = '#f59e0b';
        }
    }

    handleTournamentEnd(data) {
        const banner = document.getElementById('tournament-banner');
        if (banner) {
            banner.innerHTML = `
                <div class="tournament-content">
                    <div class="tournament-info">
                        <h3><i class="fas fa-trophy"></i> ${data.name}</h3>
                        <p>Tournament ended</p>
                    </div>
                </div>
            `;
            banner.style.background = 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)';
        }

        if (this.tournamentTimer) {
            clearInterval(this.tournamentTimer);
        }

        // Show notification
        this.showNotification('Tournament ended!', 'info');
    }

    // User Score Updates
    updateUserScore(newScore) {
        const scoreElement = document.getElementById('userScore');
        if (scoreElement) {
            // Animate score change
            const currentScore = parseInt(scoreElement.textContent);
            const difference = newScore - currentScore;
            
            if (difference > 0) {
                this.animateScoreChange(scoreElement, currentScore, newScore);
            } else {
                scoreElement.textContent = newScore;
            }
        }
    }

    animateScoreChange(element, start, end) {
        const duration = 1000;
        const startTime = performance.now();
        
        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            const currentValue = Math.floor(start + (end - start) * progress);
            element.textContent = currentValue;
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };
        
        requestAnimationFrame(animate);
    }

    // Mobile Optimization
    setupMobileOptimization() {
        // Auto-hide leaderboard sidebar on mobile
        if (window.innerWidth <= 1024) {
            const sidebar = document.getElementById('leaderboardSidebar');
            if (sidebar) {
                sidebar.classList.remove('open');
            }
        }

        // Handle window resize
        window.addEventListener('resize', () => {
            if (window.innerWidth <= 1024) {
                const mainContent = document.querySelector('.main-content');
                mainContent.classList.remove('sidebar-open');
            }
        });

        // Touch-friendly interactions
        this.setupTouchInteractions();
    }

    setupTouchInteractions() {
        // Add touch feedback to buttons
        const buttons = document.querySelectorAll('button, .action-btn, .team-manage-btn, .team-join-btn');
        buttons.forEach(button => {
            button.addEventListener('touchstart', () => {
                button.style.transform = 'scale(0.95)';
            });
            
            button.addEventListener('touchend', () => {
                button.style.transform = '';
            });
        });
    }

    // Simple onboarding tour for first-time users
    maybeShowOnboarding() {
        if (localStorage.getItem('onboarding_shown') === '1') return;
        const overlay = document.createElement('div');
        overlay.style.position = 'fixed';
        overlay.style.inset = '0';
        overlay.style.background = 'rgba(0,0,0,0.6)';
        overlay.style.zIndex = '2000';
        overlay.innerHTML = `
          <div style="max-width:520px;margin:10vh auto;background:var(--bg-primary);color:var(--text-primary);padding:24px;border-radius:12px;box-shadow:var(--shadow-xl);">
            <h2 style="margin-bottom:8px;">Welcome to HUNTING-CTF</h2>
            <p style="margin-bottom:10px;color:var(--text-secondary);">Quick tour:
            <br/>• Use the search and filters to find challenges
            <br/>• Submit flags directly on a card
            <br/>• Track live rankings in the right sidebar
            <br/>• Create or join a team from the menu
            </p>
            <div style="display:flex;gap:8px;justify-content:flex-end;">
              <button id="tourSkip" class="action-btn">Skip</button>
              <button id="tourDone" class="action-btn" style="background:var(--accent-primary);color:white;border-color:transparent;">Got it</button>
            </div>
          </div>`;
        document.body.appendChild(overlay);
        const close = () => { localStorage.setItem('onboarding_shown','1'); overlay.remove(); };
        overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
        overlay.querySelector('#tourSkip').addEventListener('click', close);
        overlay.querySelector('#tourDone').addEventListener('click', close);
    }

    // Utility Functions
    getCurrentUsername() {
        const usernameElement = document.querySelector('.username');
        return usernameElement ? usernameElement.textContent : '';
    }

    showNotification(message, type = 'info') {
        const flashMessages = document.getElementById('flashMessages') || this.createFlashContainer();
        
        const notification = document.createElement('div');
        notification.className = `flash-message flash-${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            <span>${message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        flashMessages.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    createFlashContainer() {
        const container = document.createElement('div');
        container.id = 'flashMessages';
        container.className = 'flash-messages';
        document.body.appendChild(container);
        return container;
    }

    // Performance optimizations
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    throttle(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }

    // Notification system
    setupNotifications() {
        // Load initial notification count
        this.loadNotificationCount();
        
        // Set up auto-refresh every 30 seconds
        setInterval(() => this.loadNotificationCount(), 30000);
        
        // Listen for WebSocket notifications
        if (this.socket) {
            this.socket.on('new_notification', (data) => {
                this.updateNotificationCount(data.unread_count || 1);
                this.showToastNotification(data.title, 'info');
            });
        }
    }

    async loadNotificationCount() {
        try {
            const response = await fetch('/api/notifications');
            const data = await response.json();
            
            if (data.unread_count !== undefined) {
                this.updateNotificationCount(data.unread_count);
            }
        } catch (error) {
            console.error('Error loading notification count:', error);
        }
    }

    updateNotificationCount(count) {
        const notificationCount = document.getElementById('notificationCount');
        const dropdownNotificationCount = document.getElementById('dropdownNotificationCount');
        
        if (notificationCount) {
            notificationCount.textContent = count;
            notificationCount.style.display = count > 0 ? 'inline' : 'none';
        }
        
        if (dropdownNotificationCount) {
            dropdownNotificationCount.textContent = count;
            dropdownNotificationCount.style.display = count > 0 ? 'inline' : 'none';
        }
    }

    showToastNotification(message, type = 'info') {
        // Create toast notification
        const toast = document.createElement('div');
        toast.className = `toast-notification toast-${type}`;
        toast.innerHTML = `
            <div class="toast-content">
                <i class="fas fa-${this.getToastIcon(type)}"></i>
                <span>${message}</span>
            </div>
            <button class="toast-close">&times;</button>
        `;
        
        // Add toast styles
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${this.getToastColor(type)};
            color: white;
            padding: 1rem;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 10000;
            max-width: 300px;
            animation: slideInRight 0.3s ease-out;
        `;
        
        // Add close button functionality
        const closeBtn = toast.querySelector('.toast-close');
        closeBtn.addEventListener('click', () => {
            toast.remove();
        });
        
        // Add to page
        document.body.appendChild(toast);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.remove();
            }
        }, 5000);
    }

    getToastIcon(type) {
        const icons = {
            'success': 'check-circle',
            'error': 'exclamation-circle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    getToastColor(type) {
        const colors = {
            'success': '#28a745',
            'error': '#dc3545',
            'warning': '#ffc107',
            'info': '#17a2b8'
        };
        return colors[type] || '#17a2b8';
    }

    setupNotificationSidebar() {
        // Open sidebar button
        const openSidebarBtn = document.getElementById('openNotificationSidebar');
        if (openSidebarBtn) {
            openSidebarBtn.addEventListener('click', () => this.openNotificationSidebar());
        }

        // Dropdown notification button
        const dropdownNotificationBtn = document.getElementById('dropdownNotificationBtn');
        if (dropdownNotificationBtn) {
            dropdownNotificationBtn.addEventListener('click', () => this.openNotificationSidebar());
        }

        // Close sidebar button
        const closeSidebarBtn = document.getElementById('closeSidebar');
        if (closeSidebarBtn) {
            closeSidebarBtn.addEventListener('click', () => this.closeNotificationSidebar());
        }

        // Overlay click to close sidebar
        const overlay = document.getElementById('sidebarOverlay');
        if (overlay) {
            overlay.addEventListener('click', () => this.closeNotificationSidebar());
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeNotificationSidebar();
            }
        });

        // Load notifications when sidebar opens
        this.loadNotifications();
    }

    openNotificationSidebar() {
        const sidebar = document.getElementById('notificationSidebar');
        const overlay = document.getElementById('sidebarOverlay');
        
        if (sidebar) {
            sidebar.classList.add('open');
        }
        
        if (overlay) {
            overlay.classList.add('active');
        }

        // Load fresh notifications
        this.loadNotifications();
    }

    closeNotificationSidebar() {
        const sidebar = document.getElementById('notificationSidebar');
        const overlay = document.getElementById('sidebarOverlay');
        
        if (sidebar) {
            sidebar.classList.remove('open');
        }
        
        if (overlay) {
            overlay.classList.remove('active');
        }
    }

    async loadNotifications() {
        try {
            const response = await fetch('/api/notifications');
            const data = await response.json();
            
            if (data.error) {
                console.error('Error loading notifications:', data.error);
                return;
            }
            
            this.renderNotifications(data.notifications);
        } catch (error) {
            console.error('Error loading notifications:', error);
        }
    }

    renderNotifications(notifications) {
        const notificationsList = document.getElementById('notificationsList');
        if (!notificationsList) return;

        if (notifications.length === 0) {
            notificationsList.innerHTML = `
                <div class="no-notifications">
                    <div class="empty-state">
                        <i class="fas fa-bell-slash"></i>
                        <h4>All caught up!</h4>
                        <p>No new notifications</p>
                    </div>
                </div>
            `;
            return;
        }

        const notificationsHTML = notifications.map(notification => this.createNotificationHTML(notification)).join('');
        notificationsList.innerHTML = notificationsHTML;

        // Setup mark as read functionality
        this.setupMarkAsReadListeners();
    }

    createNotificationHTML(notification) {
        const iconClass = this.getNotificationIconClass(notification.type);
        const priorityClass = notification.priority !== 'normal' ? `priority-${notification.priority}` : '';
        const timeAgo = this.formatTimeAgo(notification.created_at);
        
        return `
            <div class="notification-item ${notification.read ? '' : 'unread'} priority-${notification.priority}" data-id="${notification.id}">
                <div class="notification-icon">
                    <i class="${iconClass}"></i>
                </div>
                <div class="notification-content">
                    <div class="notification-header">
                        <h4 class="notification-title">${notification.title}</h4>
                        <span class="notification-time">${timeAgo}</span>
                    </div>
                    <p class="notification-message">${notification.message}</p>
                    <div class="notification-meta">
                        <span class="notification-type">${notification.type.replace(/_/g, ' ').toUpperCase()}</span>
                        ${notification.priority !== 'normal' ? `<span class="priority-badge ${priorityClass}">${notification.priority.toUpperCase()}</span>` : ''}
                    </div>
                </div>
                <div class="notification-actions">
                    ${!notification.read ? `
                        <button class="btn-mark-read" data-id="${notification.id}" title="Mark as read">
                            <i class="fas fa-check"></i>
                        </button>
                    ` : ''}
                </div>
            </div>
        `;
    }

    getNotificationIconClass(type) {
        const iconMap = {
            'challenge_solved': 'fas fa-trophy',
            'team_update': 'fas fa-users',
            'hint_used': 'fas fa-lightbulb',
            'achievement': 'fas fa-medal',
            'score_change': 'fas fa-chart-line',
            'default': 'fas fa-bell'
        };
        return iconMap[type] || iconMap.default;
    }

    formatTimeAgo(timeString) {
        if (!timeString) return '--';
        
        try {
            const date = new Date(timeString);
            const now = new Date();
            const diffMs = now - date;
            const diffMins = Math.floor(diffMs / 60000);
            const diffHours = Math.floor(diffMs / 3600000);
            const diffDays = Math.floor(diffMs / 86400000);
            
            if (diffMins < 1) return 'now';
            if (diffMins < 60) return `${diffMins}m`;
            if (diffHours < 24) return `${diffHours}h`;
            if (diffDays < 7) return `${diffDays}d`;
            
            return date.toLocaleDateString();
        } catch (e) {
            return '--';
        }
    }

    setupMarkAsReadListeners() {
        // Mark individual as read
        document.addEventListener('click', (e) => {
            if (e.target.closest('.btn-mark-read')) {
                const btn = e.target.closest('.btn-mark-read');
                const notificationId = btn.dataset.id;
                this.markAsRead(notificationId);
            }
        });

        // Mark all as read
        const markAllReadBtn = document.getElementById('markAllRead');
        if (markAllReadBtn) {
            markAllReadBtn.addEventListener('click', () => this.markAllAsRead());
        }

        // Refresh notifications
        const refreshBtn = document.getElementById('refreshNotifications');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadNotifications());
        }
    }

    async markAsRead(notificationId) {
        try {
            const response = await fetch(`/api/notifications/mark_read/${notificationId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            const data = await response.json();
            if (data.success) {
                const notificationItem = document.querySelector(`[data-id="${notificationId}"]`);
                if (notificationItem) {
                    notificationItem.classList.remove('unread');
                    notificationItem.style.transition = 'all 0.3s ease';
                    notificationItem.style.background = 'var(--bg-secondary)';
                    
                    const markReadBtn = notificationItem.querySelector('.btn-mark-read');
                    if (markReadBtn) {
                        markReadBtn.style.opacity = '0';
                        setTimeout(() => {
                            markReadBtn.remove();
                        }, 300);
                    }
                }
                
                this.updateNotificationCount();
            }
        } catch (error) {
            console.error('Error marking notification as read:', error);
        }
    }

    async markAllAsRead() {
        try {
            const response = await fetch('/api/notifications/mark_all_read', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            const data = await response.json();
            if (data.success) {
                const unreadNotifications = document.querySelectorAll('.notification-item.unread');
                unreadNotifications.forEach(item => {
                    item.classList.remove('unread');
                    item.style.transition = 'all 0.3s ease';
                    item.style.background = 'var(--bg-secondary)';
                    
                    const markReadBtn = item.querySelector('.btn-mark-read');
                    if (markReadBtn) {
                        markReadBtn.style.opacity = '0';
                        setTimeout(() => {
                            markReadBtn.remove();
                        }, 300);
                    }
                });
                
                this.updateNotificationCount(0);
                this.showSuccessFeedback();
            }
        } catch (error) {
            console.error('Error marking all notifications as read:', error);
        }
    }

    showSuccessFeedback() {
        const markAllReadBtn = document.getElementById('markAllRead');
        if (markAllReadBtn) {
            const originalText = markAllReadBtn.innerHTML;
            markAllReadBtn.innerHTML = '<i class="fas fa-check"></i>';
            markAllReadBtn.style.background = '#28a745';
            
            setTimeout(() => {
                markAllReadBtn.innerHTML = originalText;
                markAllReadBtn.style.background = 'rgba(255, 255, 255, 0.2)';
            }, 2000);
        }
    }
}

// Global function for scroll to challenges
function scrollToChallenges() {
    const challengesSection = document.getElementById('challenges-section');
    if (challengesSection) {
        challengesSection.scrollIntoView({ 
            behavior: 'smooth',
            block: 'start'
        });
    }
}

// Initialize the enhanced dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new DashboardEnhanced();
});

// Export for potential external use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DashboardEnhanced;
}
