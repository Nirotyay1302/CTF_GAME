// Enhanced Modern Notification Sidebar JavaScript with Performance Optimizations
document.addEventListener('DOMContentLoaded', function() {
    const socket = io();

    // Performance tracking
    const startTime = performance.now();

    // Initialize notifications with optimizations
    setupNotifications();
    setupEventListeners();
    setupSidebar();
    setupPerformanceOptimizations();

    // Log initialization time
    console.log(`Notifications initialized in ${(performance.now() - startTime).toFixed(2)}ms`);

    // Join notifications room
    socket.emit('join_notifications');
    
    // Listen for new notifications
    socket.on('new_notification', function(data) {
        addNewNotification(data);
        updateNotificationCount();
    });
    
    // Listen for notifications joined confirmation
    socket.on('notifications_joined', function(data) {
        console.log('Joined notifications room for user:', data.user_id);
    });
});

function setupSidebar() {
    const sidebar = document.getElementById('notificationSidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    // Auto-open sidebar after page load
    setTimeout(() => {
        if (sidebar) {
            sidebar.classList.add('open');
        }
        if (overlay) {
            overlay.classList.add('active');
        }
    }, 300);
}

function setupNotifications() {
    // Load initial notification count
    loadNotificationCount();
    
    // Refresh notifications every 30 seconds
    setInterval(refreshNotifications, 30000);
}

function setupEventListeners() {
    // Mark all as read button
    const markAllReadBtn = document.getElementById('markAllRead');
    if (markAllReadBtn) {
        markAllReadBtn.addEventListener('click', markAllAsRead);
    }
    
    // Refresh button
    const refreshBtn = document.getElementById('refreshNotifications');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshNotifications);
    }
    
    // Close sidebar button
    const closeSidebarBtn = document.getElementById('closeSidebar');
    if (closeSidebarBtn) {
        closeSidebarBtn.addEventListener('click', closeSidebar);
    }
    
    // Overlay click to close sidebar
    const overlay = document.getElementById('sidebarOverlay');
    if (overlay) {
        overlay.addEventListener('click', closeSidebar);
    }
    
    // Individual mark as read buttons
    document.addEventListener('click', function(e) {
        if (e.target.closest('.btn-mark-read')) {
            const btn = e.target.closest('.btn-mark-read');
            const notificationId = btn.dataset.id;
            markAsRead(notificationId);
        }
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeSidebar();
        }
        
        if (e.key === 'r' && (e.ctrlKey || e.metaKey)) {
            e.preventDefault();
            refreshNotifications();
        }
    });
}

function closeSidebar() {
    const sidebar = document.getElementById('notificationSidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebar) {
        sidebar.classList.remove('open');
    }
    
    if (overlay) {
        overlay.classList.remove('active');
    }
    
    // Redirect to dashboard after animation
    setTimeout(() => {
        window.location.href = '/dashboard/enhanced';
    }, 300);
}

function loadNotificationCount() {
    fetch('/api/notifications')
        .then(response => response.json())
        .then(data => {
            updateNotificationCount(data.unread_count);
        })
        .catch(error => {
            console.error('Error loading notification count:', error);
        });
}

function refreshNotifications() {
    const refreshBtn = document.getElementById('refreshNotifications');
    if (refreshBtn) {
        refreshBtn.style.transform = 'rotate(360deg)';
        setTimeout(() => {
            refreshBtn.style.transform = 'rotate(0deg)';
        }, 500);
    }
    
    location.reload();
}

function markAsRead(notificationId) {
    fetch(`/api/notifications/mark_read/${notificationId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const notificationItem = document.querySelector(`[data-id="${notificationId}"]`);
            if (notificationItem) {
                // Smooth transition to read state
                notificationItem.classList.remove('unread');
                notificationItem.style.transition = 'all 0.3s ease';
                notificationItem.style.background = '#f8f9fa';
                
                // Remove the mark as read button
                const markReadBtn = notificationItem.querySelector('.btn-mark-read');
                if (markReadBtn) {
                    markReadBtn.style.opacity = '0';
                    setTimeout(() => {
                        markReadBtn.remove();
                    }, 300);
                }
                
                // Update count
                updateNotificationCount();
            }
        }
    })
    .catch(error => {
        console.error('Error marking notification as read:', error);
    });
}

function markAllAsRead() {
    fetch('/api/notifications/mark_all_read', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Mark all notifications as read visually
            const unreadNotifications = document.querySelectorAll('.notification-item.unread');
            unreadNotifications.forEach(item => {
                item.classList.remove('unread');
                item.style.transition = 'all 0.3s ease';
                item.style.background = '#f8f9fa';
                
                // Remove mark as read buttons
                const markReadBtn = item.querySelector('.btn-mark-read');
                if (markReadBtn) {
                    markReadBtn.style.opacity = '0';
                    setTimeout(() => {
                        markReadBtn.remove();
                    }, 300);
                }
            });
            
            // Update count
            updateNotificationCount(0);
            
            // Show success feedback
            showSuccessFeedback();
        }
    })
    .catch(error => {
        console.error('Error marking all notifications as read:', error);
    });
}

function updateNotificationCount(count) {
    // Update the count in the header if it exists
    const countElement = document.querySelector('.notification-count');
    if (countElement) {
        countElement.textContent = count || 0;
    }
    
    // Update unread indicators
    const unreadItems = document.querySelectorAll('.notification-item.unread');
    const actualCount = count !== undefined ? count : unreadItems.length;
    
    // Update page title
    if (actualCount > 0) {
        document.title = `(${actualCount}) Notifications - CTF Challenge`;
    } else {
        document.title = 'Notifications - CTF Challenge';
    }
}

function addNewNotification(notificationData) {
    const notificationsList = document.querySelector('.notifications-list');
    if (!notificationsList) return;
    
    // Create new notification element
    const notificationItem = createNotificationElement(notificationData);
    
    // Add to the top of the list
    notificationsList.insertBefore(notificationItem, notificationsList.firstChild);
    
    // Add entrance animation
    notificationItem.style.opacity = '0';
    notificationItem.style.transform = 'translateY(-20px)';
    
    setTimeout(() => {
        notificationItem.style.transition = 'all 0.3s ease';
        notificationItem.style.opacity = '1';
        notificationItem.style.transform = 'translateY(0)';
    }, 100);
    
    // Update count
    updateNotificationCount();
    
    // Show toast notification
    showToastNotification(notificationData);
}

function createNotificationElement(data) {
    const item = document.createElement('div');
    item.className = 'notification-item unread';
    item.dataset.id = data.id;
    item.dataset.priority = data.priority || 'normal';
    
    const iconClass = getNotificationIconClass(data.type);
    const priorityClass = data.priority !== 'normal' ? `priority-${data.priority}` : '';
    
    item.innerHTML = `
        <div class="notification-icon">
            <i class="${iconClass}"></i>
        </div>
        <div class="notification-content">
            <div class="notification-header">
                <h4 class="notification-title">${data.title}</h4>
                <span class="notification-time">${formatTime(data.created_at)}</span>
            </div>
            <p class="notification-message">${data.message}</p>
            <div class="notification-meta">
                <span class="notification-type">${data.type.replace(/_/g, ' ').toUpperCase()}</span>
                ${data.priority !== 'normal' ? `<span class="priority-badge ${priorityClass}">${data.priority.toUpperCase()}</span>` : ''}
            </div>
        </div>
        <div class="notification-actions">
            <button class="btn-mark-read" data-id="${data.id}" title="Mark as read">
                <i class="fas fa-check"></i>
            </button>
        </div>
    `;
    
    return item;
}

function getNotificationIconClass(type) {
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

function formatTime(timeString) {
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

function showSuccessFeedback() {
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

function showToastNotification(data) {
    // Create toast element
    const toast = document.createElement('div');
    toast.className = 'toast-notification';
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: white;
        border-radius: 12px;
        padding: 16px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.12);
        z-index: 10001;
        max-width: 300px;
        transform: translateX(100%);
        transition: transform 0.3s ease;
        border-left: 4px solid #667eea;
    `;
    
    toast.innerHTML = `
        <div style="display: flex; align-items: flex-start; gap: 12px;">
            <div style="width: 24px; height: 24px; border-radius: 50%; background: #667eea; display: flex; align-items: center; justify-content: center; color: white; font-size: 0.8rem;">
                <i class="${getNotificationIconClass(data.type)}"></i>
            </div>
            <div style="flex: 1;">
                <div style="font-weight: 600; font-size: 0.9rem; margin-bottom: 4px;">${data.title}</div>
                <div style="font-size: 0.8rem; color: #666; line-height: 1.3;">${data.message}</div>
            </div>
        </div>
    `;
    
    document.body.appendChild(toast);
    
    // Animate in
    setTimeout(() => {
        toast.style.transform = 'translateX(0)';
    }, 100);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }, 5000);
}

// Add smooth scrolling for better UX
document.addEventListener('DOMContentLoaded', function() {
    const sidebarContent = document.querySelector('.sidebar-content');
    if (sidebarContent) {
        sidebarContent.style.scrollBehavior = 'smooth';
    }
});

// Performance optimizations for notifications
function setupPerformanceOptimizations() {
    // Debounce notification updates
    let updateTimeout;
    const originalUpdateCount = window.updateNotificationCount;
    if (originalUpdateCount) {
        window.updateNotificationCount = function(count) {
            clearTimeout(updateTimeout);
            updateTimeout = setTimeout(() => {
                originalUpdateCount(count);
            }, 100);
        };
    }

    // Memory management - limit notifications in DOM
    const maxNotifications = 50;
    function cleanupOldNotifications() {
        const items = document.querySelectorAll('.notification-item');
        if (items.length > maxNotifications) {
            for (let i = maxNotifications; i < items.length; i++) {
                items[i].remove();
            }
        }
    }

    // Run cleanup periodically
    setInterval(cleanupOldNotifications, 30000); // Every 30 seconds

    // Optimize animations for accessibility
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (prefersReducedMotion.matches) {
        // Disable animations for users who prefer reduced motion
        document.documentElement.style.setProperty('--animation-duration', '0s');
    }

    // Intersection observer for performance
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const item = entry.target;
                item.classList.add('visible');
            }
        });
    });

    // Observe notification items
    document.querySelectorAll('.notification-item').forEach(item => {
        observer.observe(item);
    });
}
