// Utility Functions

// Format timestamp to time string
function formatTime(timestamp) {
    // Ensure timestamp is treated as UTC for consistent display
    const date = new Date(timestamp + 'Z'); // Append 'Z' to treat as UTC
    return date.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Get user initial from username
function getUserInitial(username) {
    return username.charAt(0).toUpperCase();
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Generate unique ID
function generateId() {
    return Date.now().toString() + Math.random().toString(36).substr(2, 9);
}

// Get icon emoji for room type
function getIconEmoji(icon) {
    switch (icon) {
        case 'globe': return '🌍';
        case 'users': return '👥';
        default: return '💬';
    }
}

// Show toast notification
function showToast(message, type = 'info', title = null) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const iconMap = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };
    
    toast.innerHTML = `
        <div class="toast-icon">${iconMap[type]}</div>
        <div class="toast-content">
            ${title ? `<div class="toast-title">${escapeHtml(title)}</div>` : ''}
            <div class="toast-description">${escapeHtml(message)}</div>
        </div>
    `;
    
    container.appendChild(toast);
    
    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 100);
    
    // Remove toast after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            if (container.contains(toast)) {
                container.removeChild(toast);
            }
        }, 300);
    }, 3000);
}

// Auto-resize textarea
function autoResizeTextarea(textarea) {
    textarea.style.height = 'auto';
    textarea.style.height = Math.min(textarea.scrollHeight, 120) + 'px';
}

// Scroll element to bottom
function scrollToBottom(element) {
    if (element) {
        element.scrollTop = element.scrollHeight;
    }
}

// Debounce function
function debounce(func, wait) {
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

// Throttle function
function throttle(func, limit) {
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

// Check if element is in viewport
function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

// Add class with animation
function addClassWithAnimation(element, className, animationClass = 'fade-in') {
    element.classList.add(animationClass);
    element.classList.add(className);
    
    // Remove animation class after animation completes
    element.addEventListener('animationend', () => {
        element.classList.remove(animationClass);
    }, { once: true });
}

// Remove class with animation
function removeClassWithAnimation(element, className, animationClass = 'fade-out') {
    element.classList.add(animationClass);
    
    element.addEventListener('animationend', () => {
        element.classList.remove(animationClass);
        element.classList.remove(className);
    }, { once: true });
}

// Simulate API delay
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Local storage helpers
const storage = {
    get: (key, defaultValue = null) => {
        try {
            const item = localStorage.getItem(key);
            return item ? JSON.parse(item) : defaultValue;
        } catch (error) {
            console.error('Error reading from localStorage:', error);
            return defaultValue;
        }
    },
    
    set: (key, value) => {
        try {
            localStorage.setItem(key, JSON.stringify(value));
            return true;
        } catch (error) {
            console.error('Error writing to localStorage:', error);
            return false;
        }
    },
    
    remove: (key) => {
        try {
            localStorage.removeItem(key);
            return true;
        } catch (error) {
            console.error('Error removing from localStorage:', error);
            return false;
        }
    }
};

// Event emitter for communication between components
class EventEmitter {
    constructor() {
        this.events = {};
    }
    
    on(event, callback) {
        if (!this.events[event]) {
            this.events[event] = [];
        }
        this.events[event].push(callback);
    }
    
    off(event, callback) {
        if (!this.events[event]) return;
        this.events[event] = this.events[event].filter(cb => cb !== callback);
    }
    
    emit(event, data) {
        if (!this.events[event]) return;
        this.events[event].forEach(callback => callback(data));
    }
}

// Global event emitter instance
window.eventEmitter = new EventEmitter();

// Initialize Socket.IO connection if available
if (typeof io !== 'undefined') {
    window.socket = io();
}

// UI Component Handlers

// Emoji Picker Component
class EmojiPicker {
    constructor() {
        this.element = document.getElementById('emoji-picker');
        this.visible = false;
        this.bindEvents();
    }
    
    bindEvents() {
        // Handle emoji clicks
        this.element.addEventListener('click', (e) => {
            if (e.target.classList.contains('emoji')) {
                const emoji = e.target.dataset.emoji;
                window.eventEmitter.emit('emoji-selected', emoji);
                this.hide();
            }
        });
        
        // Close on outside click
        document.addEventListener('click', (e) => {
            if (!this.element.contains(e.target) && 
                !e.target.closest('#emoji-btn') && 
                !e.target.closest('#emoji-toggle')) {
                this.hide();
            }
        });
        
        // Close on escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.visible) {
                this.hide();
            }
        });
    }
    
    show() {
        this.element.classList.remove('hidden');
        this.visible = true;
        // Hide attachment menu if open
        window.attachmentMenu?.hide();
    }
    
    hide() {
        this.element.classList.add('hidden');
        this.visible = false;
    }
    
    toggle() {
        if (this.visible) {
            this.hide();
        } else {
            this.show();
        }
    }
}

// Attachment Menu Component
class AttachmentMenu {
    constructor() {
        this.element = document.getElementById('attachment-menu');
        this.fileInput = document.getElementById('file-input');
        this.visible = false;
        this.bindEvents();
    }
    
    bindEvents() {
        // Handle attachment option clicks
        this.element.addEventListener('click', (e) => {
            const option = e.target.closest('.attachment-option');
            if (option) {
                const accept = option.dataset.accept;
                this.triggerFileInput(accept);
            }
        });
        
        // Handle file input change
        this.fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                window.eventEmitter.emit('file-selected', file);
            }
            this.fileInput.value = ''; // Reset input
            this.hide();
        });
        
        // Close on outside click
        document.addEventListener('click', (e) => {
            if (!this.element.contains(e.target) && 
                !e.target.closest('#attachment-btn') && 
                !e.target.closest('#attachment-toggle')) {
                this.hide();
            }
        });
        
        // Close on escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.visible) {
                this.hide();
            }
        });
    }
    
    triggerFileInput(accept) {
        this.fileInput.accept = accept;
        this.fileInput.click();
    }
    
    show() {
        this.element.classList.remove('hidden');
        this.visible = true;
        // Hide emoji picker if open
        window.emojiPicker?.hide();
    }
    
    hide() {
        this.element.classList.add('hidden');
        this.visible = false;
    }
    
    toggle() {
        if (this.visible) {
            this.hide();
        } else {
            this.show();
        }
    }
}

// Message Input Component
class MessageInput {
    constructor() {
        this.textarea = document.getElementById('message-input');
        this.sendButton = document.getElementById('send-button');
        this.charCount = document.getElementById('char-count');
        this.maxLength = 1000;
        this.bindEvents();
    }
    
    bindEvents() {
        // Handle input changes
        this.textarea.addEventListener('input', () => {
            this.autoResize();
            this.updateCharCount();
            this.updateSendButton();
        });
        
        // Handle keyboard shortcuts
        this.textarea.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });
        
        // Handle send button click
        this.sendButton.addEventListener('click', () => {
            this.sendMessage();
        });
        
        // Handle emoji insertion
        window.eventEmitter.on('emoji-selected', (emoji) => {
            this.insertEmoji(emoji);
        });
    }
    
    autoResize() {
        autoResizeTextarea(this.textarea);
    }
    
    updateCharCount() {
        const count = this.textarea.value.length;
        this.charCount.textContent = `${count}/${this.maxLength}`;
        
        // Change color based on count
        if (count > 900) {
            this.charCount.style.color = 'hsl(var(--error))';
        } else if (count > 800) {
            this.charCount.style.color = 'hsl(var(--warning))';
        } else {
            this.charCount.style.color = 'hsl(var(--muted-foreground))';
        }
    }
    
    updateSendButton() {
        const hasContent = this.textarea.value.trim().length > 0;
        this.sendButton.disabled = !hasContent;
        
        // Update button appearance based on state
        if (hasContent) {
            this.sendButton.classList.add('active');
            this.sendButton.title = 'Send message (Enter)';
        } else {
            this.sendButton.classList.remove('active');
            this.sendButton.title = 'Type a message first';
        }
    }
    
    insertEmoji(emoji) {
        const start = this.textarea.selectionStart;
        const end = this.textarea.selectionEnd;
        const value = this.textarea.value;
        
        this.textarea.value = value.substring(0, start) + emoji + value.substring(end);
        this.textarea.selectionStart = this.textarea.selectionEnd = start + emoji.length;
        
        // Trigger input event
        this.textarea.dispatchEvent(new Event('input'));
        this.textarea.focus();
    }
    
    sendMessage() {
        const content = this.textarea.value.trim();
        if (content) {
            window.eventEmitter.emit('message-send', content);
            this.clear();
        }
    }
    
    clear() {
        this.textarea.value = '';
        this.autoResize();
        this.updateCharCount();
        this.updateSendButton();
    }
    
    focus() {
        this.textarea.focus();
    }
}

// Room Switcher Component
class RoomSwitcher {
    constructor() {
        this.currentRoom = 'general';
        this.bindEvents();
    }
    
    bindEvents() {
        // Handle room item clicks
        document.addEventListener('click', (e) => {
            const roomItem = e.target.closest('.room-item');
            if (roomItem && !roomItem.classList.contains('disabled')) {
                const roomId = roomItem.dataset.room;
                this.switchRoom(roomId);
            }
        });
    }
    
    switchRoom(roomId) {
        if (roomId === this.currentRoom) return;
        
        // Update active state
        document.querySelectorAll('.room-item').forEach(item => {
            item.classList.remove('active');
        });
        
        const activeItem = document.querySelector(`[data-room="${roomId}"]`);
        if (activeItem) {
            activeItem.classList.add('active');
        }
        
        this.currentRoom = roomId;
        window.eventEmitter.emit('room-changed', roomId);
    }
    
    initRooms(rooms) {
        const roomSwitcherElement = document.getElementById('room-switcher');
        if (!roomSwitcherElement) return;

        // Clear existing rooms before rendering new ones
        roomSwitcherElement.innerHTML = '';

        rooms.forEach(room => {
            const roomItem = document.createElement('div');
            roomItem.className = `room-item ${this.currentRoom === room.id ? 'active' : ''} ${room.disabled ? 'disabled' : ''}`;
            roomItem.dataset.room = room.id;
            roomItem.innerHTML = `
                <span class="room-icon">${getIconEmoji(room.icon)}</span>
                <span class="room-name">${escapeHtml(room.displayName)}</span>
                ${room.disabled ? '<span class="room-lock-icon">🔒</span>' : ''}
            `;
            roomSwitcherElement.appendChild(roomItem);
        });
    }

    getCurrentRoom() {
        return this.currentRoom;
    }
}

// Message Renderer Component
class MessageRenderer {
    constructor() {
        this.container = document.getElementById('messages-container');
        this.loadingIndicator = document.getElementById('loading-indicator');
        this.noMessagesIndicator = document.getElementById('no-messages');
    }
    
    showLoading() {
        this.loadingIndicator.classList.remove('hidden');
    }
    
    hideLoading() {
        this.loadingIndicator.classList.add('hidden');
    }
    
    showNoMessages() {
        this.clear();
        this.noMessagesIndicator.classList.remove('hidden');
    }
    
    hideNoMessages() {
        this.noMessagesIndicator.classList.add('hidden');
    }
    
    clear() {
        // Remove all message elements, but keep indicators
        const messages = this.container.querySelectorAll('.message');
        messages.forEach(message => message.remove());
    }
    
    renderMessages(messages, currentUserId) {
        this.hideLoading();
        this.hideNoMessages();
        
        if (messages.length === 0) {
            this.showNoMessages();
            return;
        }
        
        messages.forEach(message => {
            this.renderMessage(message, currentUserId);
        });
        
        this.scrollToBottom();
    }
    
    renderMessage(message, currentUserId) {
        const isOwn = message.user_id === currentUserId;
        const messageEl = document.createElement('div');
        messageEl.className = `message ${isOwn ? 'own' : ''}`;
        messageEl.dataset.messageId = message.id;
        
        const userInitial = getUserInitial(message.username);
        const time = formatTime(message.created_at);

        // Determine friendship status and generate friend button HTML
        let friendButtonHtml = '';
        if (!isOwn) {
            const friendId = message.user_id;
            const friendshipStatus = window.chatApp.friends.some(f => f.id === friendId) ? 'accepted' :
                                     window.chatApp.pendingRequests.some(r => r.sender_id === friendId) ? 'pending' :
                                     'none';

            if (friendshipStatus === 'none') {
                friendButtonHtml = `<button class="message-action-btn add-friend-msg-btn" data-user-id="${message.user_id}" title="Add Friend"><i class="fas fa-user-plus"></i></button>`;
            } else if (friendshipStatus === 'pending') {
                friendButtonHtml = `<button class="message-action-btn pending-friend-msg-btn" data-user-id="${message.user_id}" title="Cancel Friend Request"><i class="fas fa-user-times"></i> Cancel</button>`;
            } else if (friendshipStatus === 'accepted') {
                friendButtonHtml = `<button class="message-action-btn dm-friend-msg-btn" data-user-id="${message.user_id}" data-username="${escapeHtml(message.username)}" title="Direct Message"><i class="fas fa-comment"></i></button>`;
            }
        }

        // Append new message only if it's not already in the DOM
        if (!document.querySelector(`[data-message-id="${message.id}"]`)) {
            let messageContentHtml = '';

            // Render content based on message type
            if (message.file_url || message.message_type === 'file' || message.message_type === 'image' || message.message_type === 'video' || message.message_type === 'document') {
                const fileUrl = message.file_url || message.content.match(/\]\(([^)]+)\)/)?.[1];
                const fileName = message.content.split('](')[0].replace(/^.*\[(.*?)/, '$1'); // Extract filename from markdown
                
                // Handle different file types
                if (message.message_type === 'image' || message.content.includes('📷 [Image')) {
                    messageContentHtml = `
                        <div class="chat-media-container">
                            <a href="${fileUrl}" target="_blank" class="chat-image-link">
                                <img src="${fileUrl}" alt="${escapeHtml(fileName)}" class="chat-image" loading="lazy">
                            </a>
                            <div class="chat-media-caption">${escapeHtml(fileName.replace('Image: ', ''))}</div>
                        </div>
                    `;
                } else if (message.message_type === 'video' || message.content.includes('🎥 [Video')) {
                    messageContentHtml = `
                        <div class="chat-media-container">
                            <video controls class="chat-video">
                                <source src="${fileUrl}" type="video/mp4">
                                Your browser does not support the video tag.
                            </video>
                            <div class="chat-media-caption">
                                <a href="${fileUrl}" target="_blank" class="chat-file-link">
                                    <i class="fas fa-download"></i> ${escapeHtml(fileName.replace('Video: ', ''))}
                                </a>
                            </div>
                        </div>
                    `;
                } else if (message.message_type === 'document' || message.content.includes('📄 [Document')) {
                    messageContentHtml = `<a href="${fileUrl}" target="_blank" class="chat-file-link"><i class="fas fa-file-alt"></i> ${escapeHtml(fileName.replace('Document: ', ''))}</a>`;
                } else {
                    messageContentHtml = `<a href="${fileUrl}" target="_blank" class="chat-file-link"><i class="fas fa-file"></i> ${escapeHtml(fileName.replace('File: ', ''))}</a>`;
                }
            } else {
                messageContentHtml = `<p class="message-text">${escapeHtml(message.content)}</p>`;
            }

            messageEl.innerHTML = `
                <div class="message-avatar">
                    ${message.user_avatar ? `<img src="${message.user_avatar}" alt="${escapeHtml(message.username)}" />` : userInitial}
                </div>
                <div class="message-content">
                    <div class="message-header">
                        ${!isOwn ? `<span class="message-username">${escapeHtml(message.username)}</span>` : ''}
                        <span class="message-time">${time}</span>
                        ${friendButtonHtml}
                    </div>
                    <div class="message-bubble">
                        ${messageContentHtml}
                    </div>
                </div>
            `;

            // Add fade-in animation
            messageEl.classList.add('fade-in');
            this.container.appendChild(messageEl);
        }

        this.scrollToBottom();
    }
    
    scrollToBottom() {
        scrollToBottom(this.container);
    }
}

// Chat Header Component
class ChatHeader {
    constructor() {
        this.titleElement = document.getElementById('chat-title');
        this.subtitleElement = document.getElementById('chat-subtitle');
        this.iconElement = document.getElementById('current-room-icon');
    }
    
    updateRoom(roomData) {
        this.titleElement.textContent = roomData.displayName;
        this.subtitleElement.textContent = roomData.description;
        this.iconElement.textContent = getIconEmoji(roomData.icon);
    }
}

// Initialize all components when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM content loaded, initializing components...');
    
    // Initialize components
    window.emojiPicker = new EmojiPicker();
    window.attachmentMenu = new AttachmentMenu();
    window.messageInput = new MessageInput();
    window.roomSwitcher = new RoomSwitcher();
    window.messageRenderer = new MessageRenderer();
    window.chatHeader = new ChatHeader();
    
    console.log('Basic components initialized, now initializing FriendManager...');
    
    // Initialize FriendManager first
    window.friendManager = new FriendManager();
    
    console.log('FriendManager initialized:', window.friendManager ? 'success' : 'failed');
    console.log('Notifications panel element:', window.friendManager.notificationsPanel ? 'found' : 'not found');
    
    // Settings functionality removed
    
    // Bind global button events
    document.getElementById('emoji-btn')?.addEventListener('click', () => {
        window.emojiPicker.toggle();
    });
    
    document.getElementById('emoji-toggle')?.addEventListener('click', () => {
        window.emojiPicker.toggle();
    });
    
    document.getElementById('attachment-btn')?.addEventListener('click', () => {
        window.attachmentMenu.toggle();
    });
    
    document.getElementById('attachment-toggle')?.addEventListener('click', () => {
        window.attachmentMenu.toggle();
    });
    
    // Notifications button is now handled in FriendManager.bindEvents()
    
    // Settings functionality removed

    // Handle Return to Game button
    document.getElementById('return-to-game-btn')?.addEventListener('click', () => {
        window.location.href = '/dashboard';
    });
});

class ChatApp {
    constructor() {
        this.currentRoom = 'general';
        this.messages = [];
        this.loading = false;
        
        // Initialize Socket.IO here if it's not already global
        if (typeof io !== 'undefined' && !window.socket) {
            window.socket = io();
        }
        this.loadInitialData(); // Start loading data immediately
    }
    
    init() {
        // This method is no longer needed as loadInitialData is called in the constructor
    }
    
    async loadInitialData() {
        try {
            const response = await fetch('/api/chat/initial_data'); // New API endpoint to fetch initial data
            if (!response.ok) {
                throw new Error('Failed to fetch initial chat data');
            }
            const data = await response.json();
            this.currentUser = data.currentUser;
            this.chatRooms = data.chatRooms;
            this.friends = data.friends || []; // Fetch friends data
            this.pendingRequests = data.pendingRequests || []; // Fetch pending requests
            
            // Initialize room switcher with fetched rooms
            window.roomSwitcher.initRooms(this.chatRooms);
            window.chatHeader.updateRoom(this.getCurrentRoom());

            this.bindEvents(); // Bind events after data is loaded
            this.loadMessages();
        } catch (error) {
            console.error('Error loading initial chat data:', error);
            showToast('Failed to initialize chat', 'error', 'Error');
        }
    }
    
    async loadRooms() {
        try {
            const response = await fetch('/api/chat/initial_data');
            if (!response.ok) {
                throw new Error('Failed to fetch chat rooms');
            }
            const data = await response.json();
            this.chatRooms = data.chatRooms;
            this.friends = data.friends || [];
            
            // Update room switcher with new rooms
            window.roomSwitcher.initRooms(this.chatRooms);
            
            // If current room is no longer available, switch to general
            if (!this.chatRooms.find(r => r.id === this.currentRoom)) {
                this.switchRoom('general');
            }
        } catch (error) {
            console.error('Error loading chat rooms:', error);
            showToast('Failed to update chat rooms', 'error', 'Error');
        }
    }

    bindEvents() {
        window.eventEmitter.on('room-changed', (roomId) => {
            this.switchRoom(roomId);
        });

        window.eventEmitter.on('message-send', (content) => {
            this.sendMessage(content);
        });

        window.eventEmitter.on('file-selected', (file) => {
            this.uploadFile(file);
        });
        
        // SocketIO events
        if (window.socket) {
            window.socket.on('new_message', (message) => {
                if (message.room === this.currentRoom) {
                    this.messages.push(message);
                    window.messageRenderer.renderMessage(message, this.currentUser.id);
                }
            });
            window.socket.on('status', (data) => {
                showToast(data.message, 'info', 'Chat Status');
            });
            window.socket.on('friend_online', (data) => {
                showToast(`${data.username} is online!`, 'info', 'Friend Status');
                // TODO: Update friend list UI
            });
            window.socket.on('friend_offline', (data) => {
                showToast(`${data.username} is offline.`, 'info', 'Friend Status');
                // TODO: Update friend list UI
            });

            // Handle friend requests and direct messages from message buttons
            document.addEventListener('click', async (e) => {
                // Handle add friend button clicks
                const addFriendTarget = e.target.closest('.add-friend-msg-btn');
                if (addFriendTarget) {
                    const friendId = addFriendTarget.dataset.userId;
                    const username = addFriendTarget.dataset.username;
                    if (friendId) {
                        try {
                            // Show confirmation dialog before sending request
                            if (!confirm(`Send friend request to ${username}?`)) {
                                return; // User cancelled
                            }
                            
                            addFriendTarget.disabled = true;
                            addFriendTarget.innerHTML = '<i class="fas fa-spinner fa-spin"></i>'; // Show loading spinner

                            const formData = new FormData();
                            formData.append('friend_id', friendId);

                            const response = await fetch('/friends/request', {
                                method: 'POST',
                                body: formData
                            });

                            if (!response.ok) {
                                const errorData = await response.json();
                                throw new Error(errorData.message || 'Failed to send friend request');
                            }

                            const result = await response.json();
                            if (result.success) {
                                showToast(`Friend request sent to ${username}`, 'success', 'Friend Request Sent');
                                addFriendTarget.innerHTML = '<i class="fas fa-user-clock"></i> Pending'; // Better pending indicator
                                addFriendTarget.classList.remove('add-friend-msg-btn');
                                addFriendTarget.classList.add('pending-friend-msg-btn');
                                
                                // Refresh friend requests in notification panel if open
                                if (window.friendManager && !window.friendManager.notificationsPanel.classList.contains('hidden')) {
                                    window.friendManager.loadFriendRequests();
                                }
                            } else {
                                throw new Error(result.message || 'Failed to send friend request');
                            }
                        } catch (error) {
                            console.error('Error sending friend request from message:', error);
                            showToast(error.message, 'error', 'Friend Request Failed');
                            addFriendTarget.innerHTML = '<i class="fas fa-user-plus"></i> Add Friend'; // Revert icon on error
                            addFriendTarget.disabled = false;
                        }
                    }
                }
                
                // Handle pending friend request cancel button clicks
                const pendingTarget = e.target.closest('.pending-friend-msg-btn');
                if (pendingTarget) {
                    const friendId = pendingTarget.dataset.userId;
                    if (friendId && confirm('Cancel this friend request?')) {
                        try {
                            pendingTarget.disabled = true;
                            pendingTarget.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
                            
                            const response = await fetch(`/friends/cancel/${friendId}`, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'X-Requested-With': 'XMLHttpRequest'
                                }
                            });
                            
                            if (!response.ok) {
                                const errorData = await response.json();
                                throw new Error(errorData.message || 'Failed to cancel friend request');
                            }
                            
                            const result = await response.json();
                            if (result.success) {
                                showToast('Friend request cancelled', 'success');
                                pendingTarget.innerHTML = '<i class="fas fa-user-plus"></i> Add Friend';
                                pendingTarget.classList.remove('pending-friend-msg-btn');
                                pendingTarget.classList.add('add-friend-msg-btn');
                                pendingTarget.disabled = false;
                            } else {
                                throw new Error(result.message || 'Failed to cancel friend request');
                            }
                        } catch (error) {
                            console.error('Error cancelling friend request:', error);
                            showToast(error.message, 'error');
                            pendingTarget.innerHTML = '<i class="fas fa-user-times"></i> Cancel';
                            pendingTarget.disabled = false;
                        }
                    }
                }
                
                // Handle direct message button clicks
                const dmTarget = e.target.closest('.dm-friend-msg-btn');
                if (dmTarget) {
                    const friendId = dmTarget.dataset.userId;
                    const friendName = dmTarget.dataset.username;
                    if (friendId && friendName) {
                        // Create room ID for private chat (sort user IDs to ensure consistency)
                        const roomUsers = [this.currentUser.id, parseInt(friendId)].sort((a, b) => a - b);
                        const privateRoomId = `private-${roomUsers[0]}-${roomUsers[1]}`;
                        
                        // Find if this room already exists in chat rooms
                        const existingRoom = this.chatRooms.find(r => r.id === privateRoomId);
                        
                        if (existingRoom) {
                            // Switch to existing private chat room
                            this.switchRoom(privateRoomId);
                        } else {
                            // This shouldn't happen as rooms are loaded from the server,
                            // but we'll handle it by refreshing the room list
                            showToast(`Starting chat with ${friendName}`, 'info', 'Direct Message');
                            await this.loadRooms();
                            
                            // Try to find the room again after refresh
                            const refreshedRoom = this.chatRooms.find(r => r.id === privateRoomId);
                            if (refreshedRoom) {
                                this.switchRoom(privateRoomId);
                            } else {
                                showToast('Could not start private chat. Please try again.', 'error', 'Error');
                            }
                        }
                    }
                }
            });
        }
    }

    async loadMessages() {
        this.loading = true;
        window.messageRenderer.showLoading();
        window.messageRenderer.clear(); // Explicitly clear existing messages
        try {
            const response = await fetch(`/api/chat/messages?room=${this.currentRoom}`);
            if (!response.ok) {
                throw new Error('Failed to fetch messages');
            }
            this.messages = await response.json();
            window.messageRenderer.renderMessages(this.messages, this.currentUser.id);
        } catch (error) {
            console.error('Error loading messages:', error);
            showToast('Failed to load messages', 'error', 'Error');
        } finally {
            this.loading = false;
        }
    }

    async sendMessage(content) {
        if (!content.trim()) return;

        try {
            const response = await fetch('/api/chat/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ content: content, room: this.currentRoom })
            });

            if (!response.ok) {
                throw new Error('Failed to send message');
            }
            const message = await response.json();
            
            // Optimistically add message to UI for sender
            if (message && message.id && message.user_id === this.currentUser.id) {
                this.messages.push(message);
                window.messageRenderer.renderMessage(message, this.currentUser.id);
            }

            showToast('Your message has been delivered', 'success', 'Message sent');
        } catch (error) {
            console.error('Error sending message:', error);
            showToast('Failed to send message', 'error', 'Error');
        }
    }

    async switchRoom(roomId) {
        const room = this.chatRooms.find(r => r.id === roomId);
        if (!room || room.disabled) return;

        if (roomId === this.currentRoom) return;

        // Leave current room in SocketIO
        if (window.socket) {
            window.socket.emit('leave_chat', { room: this.currentRoom });
        }

        this.currentRoom = roomId;

        // Join new room in SocketIO
        if (window.socket) {
            window.socket.emit('join_chat', { room: this.currentRoom });
        }

        // Update chat header
        window.chatHeader.updateRoom(room);

        // Load messages for new room
        await this.loadMessages();

        showToast(`Switched to ${room.displayName}`, 'info', 'Room changed');
    }

    async uploadFile(file) {
        const maxSize = 10 * 1024 * 1024; // 10MB
        if (file.size > maxSize) {
            showToast('File size must be less than 10MB', 'error', 'File too large');
            return;
        }

        try {
            showToast('File upload in progress', 'info', 'Uploading...');

            const formData = new FormData();
            formData.append('file', file);
            formData.append('room', this.currentRoom);

            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error('Failed to upload file');
            }
            const result = await response.json();
            if (result.success) {
                showToast('File has been uploaded successfully', 'success', 'File uploaded');
                // The new message with the file will be emitted via SocketIO
            } else {
                throw new Error(result.message || 'Unknown upload error');
            }
        } catch (error) {
            console.error('Error uploading file:', error);
            showToast('Failed to upload file', 'error', 'Upload failed');
        }
    }

    getCurrentRoom() {
        return this.chatRooms.find(r => r.id === this.currentRoom);
    }

    getCurrentUser() {
        return this.currentUser;
    }
}

// Initialize the chat application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Socket.IO client here
    if (typeof io !== 'undefined') {
        window.socket = io();
    }

    // The `ChatApp` constructor already calls `loadInitialData` which then binds events.
    // This timeout ensures all other components are initialized before ChatApp.
    setTimeout(() => {
        window.chatApp = new ChatApp();
        // FriendManager is already initialized above
        
        // Focus on message input
        window.messageInput?.focus();
        
        console.log('HUNTING-CTF Chat initialized successfully!');
    }, 100);
});

// Handle window events
window.addEventListener('beforeunload', function() {
    // Save any pending data or show confirmation if needed
    // For now, just log that the user is leaving
    console.log('User leaving chat application');
});

// Handle online/offline status
window.addEventListener('online', function() {
    showToast('Connection restored', 'success', 'Online');
});

window.addEventListener('offline', function() {
    showToast('Connection lost', 'warning', 'Offline');
});

// Handle visibility change (when user switches tabs)
document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        console.log('Chat tab hidden');
    } else {
        console.log('Chat tab visible');
        // Could refresh messages here if needed
    }
});

// Expose useful functions to global scope for debugging
window.chatDebug = {
    sendTestMessage: () => {
        const testMessages = [
            'Hello from debug mode! 👋',
            'This is a test message',
            'Testing emoji support 🚀✨🔥',
            'Multi-line\nmessage\ntest'
        ];
        const randomMessage = testMessages[Math.floor(Math.random() * testMessages.length)];
        window.eventEmitter.emit('message-send', randomMessage);
    },
    
    showTestToast: (type = 'info') => {
        showToast(`This is a ${type} toast notification`, type, 'Test Toast');
    },
    
    clearMessages: () => {
        if (window.chatApp) {
            window.chatApp.messages = [];
            window.messageRenderer.clear();
            window.messageRenderer.showNoMessages();
        }
    },
    
    loadTestMessages: () => {
        if (window.chatApp) {
            window.chatApp.loadMessages();
        }
    }
};

// Friend Manager Component
class FriendManager {
    constructor() {
        this.addFriendBtn = document.getElementById('add-friend-btn');
        this.modal = document.getElementById('add-friend-modal');
        this.closeButton = this.modal?.querySelector('.close-button');
        this.searchInput = document.getElementById('friend-search-input');
        this.searchButton = document.getElementById('friend-search-btn');
        this.searchResultsContainer = document.getElementById('friend-search-results');
        
        // Notification panel elements
        this.notificationsBtn = document.getElementById('notifications-btn');
        this.notificationsPanel = document.getElementById('notifications-panel');
        this.notificationsPanelCloseBtn = this.notificationsPanel?.querySelector('.close-panel-btn');
        this.friendRequestsContainer = document.getElementById('friendRequestsContainer') || document.getElementById('friend-requests-container');
        
        // Settings panel elements removed
        
        // Friend requests data
        this.friendRequests = [];
        
        this.bindEvents();
        this.loadFriendRequests();
    }

    bindEvents() {
        // Add Friend Modal Events
        this.addFriendBtn?.addEventListener('click', () => this.showModal());
        this.closeButton?.addEventListener('click', () => this.hideModal());
        this.modal?.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.hideModal();
            }
        });
        
        // Panel close buttons
        this.notificationsPanelCloseBtn?.addEventListener('click', () => this.hideNotificationsPanel());
        
        // Panel toggle buttons
        this.notificationsBtn?.addEventListener('click', () => this.toggleNotificationsPanel());
        
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                if (this.modal && !this.modal.classList.contains('hidden')) {
                    this.hideModal();
                }
                if (this.notificationsPanel && this.notificationsPanel.style.transform !== 'translateX(100%)') {
                    this.hideNotificationsPanel();
                }
            }
        });

        this.searchButton?.addEventListener('click', () => this.searchUsers());
        this.searchInput?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                this.searchUsers();
            }
        });

        this.searchResultsContainer?.addEventListener('click', (e) => {
            const target = e.target.closest('.add-friend-btn');
            if (target) {
                const friendId = target.dataset.userId;
                if (friendId) {
                    this.sendFriendRequest(friendId, target);
                }
            }
        });
        
        // Notifications Panel Events
        this.notificationsBtn?.addEventListener('click', () => this.toggleNotificationsPanel());
        this.notificationsPanelCloseBtn?.addEventListener('click', () => this.hideNotificationsPanel());
        
        // Settings Panel Events removed
        
        // Friend Request Actions
        this.friendRequestsContainer?.addEventListener('click', (e) => {
            const acceptBtn = e.target.closest('.accept-btn');
            const rejectBtn = e.target.closest('.reject-btn');
            
            if (acceptBtn) {
                const requestId = acceptBtn.dataset.requestId;
                if (requestId) {
                    this.acceptFriendRequest(requestId, acceptBtn.closest('.friend-request-item'));
                }
            } else if (rejectBtn) {
                const requestId = rejectBtn.dataset.requestId;
                if (requestId) {
                    this.rejectFriendRequest(requestId, rejectBtn.closest('.friend-request-item'));
                }
            }
        });
        
        // Listen for new friend requests via Socket.IO
        if (window.socket) {
            window.socket.on('new_friend_request', (data) => {
                showToast(`New friend request from ${data.username}`, 'info', 'Friend Request');
                this.loadFriendRequests(); // Reload friend requests
            });
            
            window.socket.on('friend_request_accepted', (data) => {
                showToast(`${data.username} accepted your friend request`, 'success', 'Friend Request Accepted');
                // If we're in a chat room, refresh the room list to show new direct message options
                if (window.chatApp) {
                    window.chatApp.loadRooms();
                }
            });
        }
    }

    showModal() {
        this.modal?.classList.remove('hidden');
        this.searchInput?.focus();
        this.searchResultsContainer.innerHTML = '<p class="no-results">Search for users by username or email.</p>';
        
        // Show suggested friends when modal opens
        this.showSuggestedFriends();
    }

    hideModal() {
        this.modal?.classList.add('hidden');
        this.searchInput.value = ''; // Clear search input
        this.searchResultsContainer.innerHTML = '<p class="no-results">Search for users by username or email.</p>';
    }
    
    showSuggestedFriends() {
        // Show loading indicator
        this.searchResultsContainer.innerHTML = '<p class="no-results">Loading suggested users...</p>';
        
        // Get unique users from chat history who aren't already friends
        const suggestedUsers = this.getSuggestedUsersFromChatHistory();
        
        if (suggestedUsers.length > 0) {
            this.renderSearchResults(suggestedUsers);
            // Add a header to indicate these are suggestions
            const header = document.createElement('div');
            header.className = 'search-results-header';
            header.innerHTML = '<h4>Suggested Users</h4>';
            this.searchResultsContainer.insertBefore(header, this.searchResultsContainer.firstChild);
        } else {
            this.searchResultsContainer.innerHTML = '<p class="no-results">Search for users by username or email.</p>';
        }
    }
    
    getSuggestedUsersFromChatHistory() {
        // Get unique users from chat history who aren't already friends
        const suggestedUsers = [];
        const currentUserId = window.chatApp?.currentUser?.id;
        const friendIds = window.chatApp?.friends?.map(f => f.id) || [];
        const pendingRequestIds = window.chatApp?.pendingRequests?.map(r => r.sender_id) || [];
        
        // Get unique users from messages
        const seenUserIds = new Set();
        
        // Check if we have access to messages
        if (window.chatApp?.messages) {
            const messages = window.chatApp.messages;
            
            // Process messages to find unique users
            messages.forEach(message => {
                const userId = message.user_id;
                
                // Skip if it's current user, already a friend, or already in pending requests
                if (userId === currentUserId || 
                    friendIds.includes(userId) || 
                    pendingRequestIds.includes(userId) || 
                    seenUserIds.has(userId)) {
                    return;
                }
                
                seenUserIds.add(userId);
                suggestedUsers.push({
                    id: userId,
                    username: message.username,
                    profile_picture: message.user_avatar, // Use user_avatar instead of profile_picture
                    is_online: false, // We don't know their online status
                    friendship_status: 'none'
                });
            });
        }
        
        // Limit to 5 suggestions
        return suggestedUsers.slice(0, 5);
    }

    async searchUsers() {
        const query = this.searchInput.value.trim();
        if (query.length < 2) {
            this.searchResultsContainer.innerHTML = '<p class="no-results">Please enter at least 2 characters to search.</p>';
            return;
        }

        this.searchResultsContainer.innerHTML = '<p class="no-results">Searching...</p>';

        try {
            const response = await fetch(`/friends/search?q=${encodeURIComponent(query)}`);
            if (!response.ok) {
                throw new Error('Failed to search users');
            }
            const users = await response.json();
            this.renderSearchResults(users);
        } catch (error) {
            console.error('Error searching users:', error);
            this.searchResultsContainer.innerHTML = '<p class="no-results">Error searching users.</p>';
            showToast('Error searching users', 'error', 'Search Failed');
        }
    }

    renderSearchResults(users) {
        this.searchResultsContainer.innerHTML = '';
        if (users.length === 0) {
            this.searchResultsContainer.innerHTML = '<p class="no-results">No users found.</p>';
            return;
        }

        users.forEach(user => {
            const userItem = document.createElement('div');
            userItem.className = 'user-search-item';
            
            const avatarHtml = user.profile_picture 
                ? `<img src="${user.profile_picture}" alt="${escapeHtml(user.username)}" />` 
                : getUserInitial(user.username);

            let actionButtonHtml = '';
            if (user.friendship_status === 'pending') {
                actionButtonHtml = `<button class="pending-btn" disabled>Pending</button>`;
            } else if (user.friendship_status === 'accepted') {
                actionButtonHtml = `<button class="friends-btn" disabled>Friends</button>`;
            } else {
                actionButtonHtml = `<button class="add-friend-btn" data-user-id="${user.id}">Add Friend</button>`;
            }

            userItem.innerHTML = `
                <div class="user-search-avatar">${avatarHtml}</div>
                <div class="user-search-info">
                    <strong>${escapeHtml(user.username)}</strong>
                    <span>${user.is_online ? 'Online' : 'Offline'}</span>
                </div>
                <div class="user-search-actions">
                    ${actionButtonHtml}
                </div>
            `;
            this.searchResultsContainer.appendChild(userItem);
        });
    }

    // Notifications Panel Methods
    toggleNotificationsPanel() {
        console.log('Toggling notifications panel');
        
        if (this.notificationsPanel) {
            // Toggle the panel visibility using classes for better control
            if (this.notificationsPanel.classList.contains('hidden') || 
                this.notificationsPanel.style.transform === 'translateX(100%)') {
                // Show panel
                this.notificationsPanel.classList.remove('hidden');
                this.notificationsPanel.style.transform = 'translateX(0%)';
                this.loadFriendRequests(); // Refresh friend requests when panel opens
                
                // Add overlay with proper class
                let overlay = document.querySelector('.notifications-panel-overlay');
                if (!overlay) {
                    overlay = document.createElement('div');
                    overlay.className = 'notifications-panel-overlay';
                    overlay.addEventListener('click', () => this.hideNotificationsPanel());
                    document.body.appendChild(overlay);
                }
                
                // Set display to block before adding active class
                overlay.style.display = 'block';
                
                // Use setTimeout to ensure the display change takes effect before adding active class
                setTimeout(() => {
                    overlay.classList.add('active');
                }, 10);
            } else {
                // Hide panel
                this.hideNotificationsPanel();
            }
        } else {
            console.error('Notifications panel element not found');
            // Create the notifications panel if it doesn't exist
            this.createNotificationsPanel();
        }
    }
    
    hideNotificationsPanel() {
        if (this.notificationsPanel) {
            // Then set transform immediately
            this.notificationsPanel.style.transform = 'translateX(100%)';
            
            // Handle overlay with proper fade out
            const overlay = document.querySelector('.notifications-panel-overlay');
            if (overlay) {
                overlay.classList.remove('active');
                
                // Remove overlay after transition completes
                setTimeout(() => {
                    overlay.style.display = 'none';
                }, 300); // Match the CSS transition time
            }
        }
    }
    
    // Settings Panel Methods removed
    
    // Settings methods removed
    
    createNotificationsPanel() {
        // Create the notifications panel if it doesn't exist
        console.log('Creating notifications panel');
        
        // Create the panel element
        this.notificationsPanel = document.createElement('div');
        this.notificationsPanel.className = 'side-panel notifications-panel';
        this.notificationsPanel.id = 'notifications-panel';
        
        // Create panel header
        const panelHeader = document.createElement('div');
        panelHeader.className = 'panel-header';
        
        const panelTitle = document.createElement('h3');
        panelTitle.textContent = 'Notifications';
        
        const closeButton = document.createElement('button');
        closeButton.className = 'close-panel-btn';
        closeButton.innerHTML = '&times;';
        closeButton.addEventListener('click', () => this.hideNotificationsPanel());
        
        panelHeader.appendChild(panelTitle);
        panelHeader.appendChild(closeButton);
        
        // Create panel content
        const panelContent = document.createElement('div');
        panelContent.className = 'panel-content';
        
        // Create friend requests section
        const friendRequestsSection = document.createElement('div');
        friendRequestsSection.className = 'friend-requests-section';
        
        const friendRequestsTitle = document.createElement('h4');
        friendRequestsTitle.textContent = 'Friend Requests';
        
        const friendRequestsContainer = document.createElement('div');
        friendRequestsContainer.className = 'friend-requests-container';
        friendRequestsContainer.id = 'friendRequestsContainer';
        this.friendRequestsContainer = friendRequestsContainer;
        
        friendRequestsSection.appendChild(friendRequestsTitle);
        friendRequestsSection.appendChild(friendRequestsContainer);
        
        // Create notifications section
        const notificationsSection = document.createElement('div');
        notificationsSection.className = 'notifications-section';
        
        const notificationsTitle = document.createElement('h4');
        notificationsTitle.textContent = 'Recent Notifications';
        
        const notificationsContainer = document.createElement('div');
        notificationsContainer.className = 'notifications-container';
        notificationsContainer.id = 'notificationsContainer';
        
        notificationsSection.appendChild(notificationsTitle);
        notificationsSection.appendChild(notificationsContainer);
        
        // Assemble the panel
        panelContent.appendChild(friendRequestsSection);
        panelContent.appendChild(notificationsSection);
        
        this.notificationsPanel.appendChild(panelHeader);
        this.notificationsPanel.appendChild(panelContent);
        
        // Add to the DOM
        document.body.appendChild(this.notificationsPanel);
        
        // Set up the close button
        this.notificationsPanelCloseBtn = closeButton;
        
        // Now toggle it to show
        setTimeout(() => this.toggleNotificationsPanel(), 100);
    }
    
    // Friend Requests Methods
    async loadFriendRequests() {
        if (!this.friendRequestsContainer) {
            console.error('Friend requests container not found');
            return;
        }
        
        console.log('Loading friend requests...');
        
        try {
            // Show loading indicator
            this.friendRequestsContainer.innerHTML = '<div class="loading-spinner"></div><p class="no-items-message">Loading requests...</p>';
            
            const response = await fetch('/friends/pending');
            if (!response.ok) {
                throw new Error('Failed to load friend requests');
            }
            
            const data = await response.json();
            console.log('Friend requests loaded:', data);
            this.friendRequests = data.requests || [];
            this.renderFriendRequests();
        } catch (error) {
            console.error('Error loading friend requests:', error);
            this.friendRequestsContainer.innerHTML = '<p class="no-items-message">Error loading friend requests</p>';
            // Try to load from initial data as fallback
            if (window.chatApp && window.chatApp.pendingRequests) {
                console.log('Using fallback friend requests from chatApp');
                this.friendRequests = window.chatApp.pendingRequests;
                this.renderFriendRequests();
            }
        }
    }
    
    renderFriendRequests() {
        if (!this.friendRequestsContainer) {
            console.error('Friend requests container not found');
            return;
        }
        
        if (!this.friendRequests || this.friendRequests.length === 0) {
            this.friendRequestsContainer.innerHTML = '<div class="empty-state"><i class="fas fa-user-friends"></i><p class="no-items-message">No pending friend requests</p></div>';
            return;
        }
        
        // Clear previous content
        this.friendRequestsContainer.innerHTML = '';
        
        // Sort requests by date (newest first)
        const sortedRequests = [...this.friendRequests].sort((a, b) => {
            return new Date(b.created_at) - new Date(a.created_at);
        });
        
        sortedRequests.forEach(request => {
            const requestItem = document.createElement('div');
            requestItem.className = 'friend-request-item';
            requestItem.dataset.requestId = request.id;
            
            const avatarHtml = request.profile_picture 
                ? `<img src="${request.profile_picture}" alt="${escapeHtml(request.username)}" />` 
                : getUserInitial(request.username);
                
            const timeAgo = formatTimeAgo(new Date(request.created_at));
            
            requestItem.innerHTML = `
                <div class="friend-request-info">
                    <div class="friend-request-avatar">${avatarHtml}</div>
                    <div>
                        <div class="friend-request-name">${escapeHtml(request.username)}</div>
                        <div class="friend-request-time">${timeAgo}</div>
                    </div>
                </div>
                <div class="friend-request-actions">
                    <button class="accept-btn" data-request-id="${request.id}">
                        <i class="fas fa-check"></i> Accept
                    </button>
                    <button class="reject-btn" data-request-id="${request.id}">
                        <i class="fas fa-times"></i> Reject
                    </button>
                </div>
            `;
            
            this.friendRequestsContainer.appendChild(requestItem);
            
            // Add event listeners for this specific request item's buttons
            const acceptBtn = requestItem.querySelector('.accept-btn');
            const rejectBtn = requestItem.querySelector('.reject-btn');
            
            if (acceptBtn) {
                acceptBtn.addEventListener('click', () => {
                    const requestId = acceptBtn.dataset.requestId;
                    if (requestId) {
                        this.acceptFriendRequest(requestId, requestItem);
                    }
                });
            }
            
            if (rejectBtn) {
                rejectBtn.addEventListener('click', () => {
                    const requestId = rejectBtn.dataset.requestId;
                    if (requestId) {
                        this.rejectFriendRequest(requestId, requestItem);
                    }
                });
            }
        });
    }
    
    async acceptFriendRequest(requestId, requestElement) {
        console.log('Accepting friend request:', requestId);
        
        try {
            // Disable the buttons to prevent multiple clicks
            if (requestElement) {
                const acceptBtn = requestElement.querySelector('.accept-btn');
                const rejectBtn = requestElement.querySelector('.reject-btn');
                
                if (acceptBtn) acceptBtn.disabled = true;
                if (rejectBtn) rejectBtn.disabled = true;
                
                if (acceptBtn) acceptBtn.textContent = 'Accepting...';
            }
            
            const response = await fetch(`/friends/accept/${requestId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            
            console.log('Accept friend request response status:', response.status);
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Failed to accept friend request');
            }
            
            const result = await response.json();
            console.log('Accept friend request result:', result);
            
            if (result.success) {
                showToast(result.message, 'success', 'Friend Request Accepted');
                
                // Remove the request from the list
                if (requestElement) {
                    requestElement.remove();
                    
                    // Update the friend requests count
                    this.friendRequests = this.friendRequests.filter(req => req.id !== parseInt(requestId));
                    console.log('Updated friend requests:', this.friendRequests);
                    
                    // Show no requests message if there are no more requests
                    if (this.friendRequests.length === 0) {
                        this.friendRequestsContainer.innerHTML = '<p class="no-items-message">No pending friend requests</p>';
                    }
                }
                
                // If we're in a chat room, refresh the room list to show new direct message options
                if (window.chatApp) {
                    console.log('Refreshing chat rooms');
                    window.chatApp.loadRooms();
                }
            } else {
                throw new Error(result.message || 'Failed to accept friend request');
            }
        } catch (error) {
            console.error('Error accepting friend request:', error);
            showToast(error.message, 'error', 'Friend Request Failed');
            
            // Re-enable the buttons on error
            if (requestElement) {
                const acceptBtn = requestElement.querySelector('.accept-btn');
                const rejectBtn = requestElement.querySelector('.reject-btn');
                
                if (acceptBtn) {
                    acceptBtn.disabled = false;
                    acceptBtn.textContent = 'Accept';
                }
                if (rejectBtn) rejectBtn.disabled = false;
            }
        }
    }
    
    async rejectFriendRequest(requestId, requestElement) {
        console.log('Rejecting friend request:', requestId);
        
        try {
            // Disable the buttons to prevent multiple clicks
            if (requestElement) {
                const acceptBtn = requestElement.querySelector('.accept-btn');
                const rejectBtn = requestElement.querySelector('.reject-btn');
                
                if (acceptBtn) acceptBtn.disabled = true;
                if (rejectBtn) rejectBtn.disabled = true;
                
                if (rejectBtn) rejectBtn.textContent = 'Rejecting...';
            }
            
            const response = await fetch(`/friends/reject/${requestId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            
            console.log('Reject friend request response status:', response.status);
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Failed to reject friend request');
            }
            
            const result = await response.json();
            console.log('Reject friend request result:', result);
            
            if (result.success) {
                showToast(result.message, 'success', 'Friend Request Rejected');
                
                // Remove the request from the list
                if (requestElement) {
                    requestElement.remove();
                    
                    // Update the friend requests count
                    this.friendRequests = this.friendRequests.filter(req => req.id !== parseInt(requestId));
                    console.log('Updated friend requests after rejection:', this.friendRequests);
                    
                    // Show no requests message if there are no more requests
                    if (this.friendRequests.length === 0) {
                        this.friendRequestsContainer.innerHTML = '<p class="no-items-message">No pending friend requests</p>';
                    }
                }
            } else {
                throw new Error(result.message || 'Failed to reject friend request');
            }
        } catch (error) {
            console.error('Error rejecting friend request:', error);
            showToast(error.message, 'error', 'Friend Request Failed');
            
            // Re-enable the buttons on error
            if (requestElement) {
                const acceptBtn = requestElement.querySelector('.accept-btn');
                const rejectBtn = requestElement.querySelector('.reject-btn');
                
                if (acceptBtn) acceptBtn.disabled = false;
                if (rejectBtn) {
                    rejectBtn.disabled = false;
                    rejectBtn.textContent = 'Reject';
                }
            }
        }
    }
    
    async sendFriendRequest(friendId, buttonElement) {
        try {
            buttonElement.disabled = true;
            buttonElement.textContent = 'Sending...';

            const formData = new FormData();
            formData.append('friend_id', friendId);

            const response = await fetch('/friends/request', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Failed to send friend request');
            }

            const result = await response.json();
            if (result.success) {
                showToast(result.message, 'success', 'Friend Request Sent');
                buttonElement.innerHTML = '<i class="fas fa-user-times"></i> Cancel';
                buttonElement.classList.remove('add-friend-btn');
                buttonElement.classList.add('pending-btn');
            } else {
                throw new Error(result.message || 'Failed to send friend request');
            }
        } catch (error) {
            console.error('Error sending friend request:', error);
            showToast(error.message, 'error', 'Friend Request Failed');
            buttonElement.textContent = 'Add Friend'; // Revert button on error
            buttonElement.disabled = false;
        }
    }
}