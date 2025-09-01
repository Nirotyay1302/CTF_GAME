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

        // Friend button functionality removed
        let friendButtonHtml = '';

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
    
    console.log('Basic components initialized');
    
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

    // Handle Return to Game buttons
    document.getElementById('return-to-game-btn')?.addEventListener('click', () => {
        window.location.href = '/dashboard';
    });
    
    document.getElementById('return-to-game-btn-sidebar')?.addEventListener('click', () => {
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

// Friend Manager Component and Notification Panel removed