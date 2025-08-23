// Chat System JavaScript
class ChatSystem {
    constructor() {
        this.socket = null;
        this.currentUserId = null;
        this.messages = [];
        this.isTyping = false;
        this.typingTimeout = null;
        this.hasDisconnected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupWebSocket();
        this.loadMessages();
        this.autoResizeTextarea();
        // Initialize typing indicator
        this.setupTypingIndicator();
    }

    setupEventListeners() {
        const messageInput = document.getElementById('messageInput');
        const sendBtn = document.getElementById('sendBtn');
        const charCount = document.getElementById('charCount');
        const inputWrapper = document.querySelector('.input-wrapper');

        // Message input handling
        messageInput.addEventListener('input', (e) => {
            this.handleInputChange(e);
        });

        messageInput.addEventListener('keydown', (e) => {
            this.handleKeyDown(e);
        });

        // Send button - using direct function binding to ensure 'this' context
        if (sendBtn) {
            sendBtn.addEventListener('click', this.sendMessage.bind(this));
        } else {
            console.error('Send button not found in the DOM');
        }

        // Auto-resize textarea
        messageInput.addEventListener('input', () => {
            this.autoResizeTextarea();
        });

        // Focus input on page load
        messageInput.focus();
        
        // Handle typing events
        messageInput.addEventListener('focus', () => {
            this.startTyping();
            if (inputWrapper) {
                inputWrapper.classList.add('focused');
            }
        });
        
        messageInput.addEventListener('blur', () => {
            this.stopTyping();
            if (inputWrapper) {
                inputWrapper.classList.remove('focused');
            }
        });
    }

    setupWebSocket() {
        // Initialize socket connection with enhanced reconnection options
        this.socket = io({
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionAttempts: this.maxReconnectAttempts,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            timeout: 20000
        });
        
        this.socket.on('connect', () => {
            console.log('Connected to chat server');
            this.socket.emit('join_chat');
            this.addSystemMessage('Connected to chat server');
            
            // Show reconnection message if this wasn't the first connection
            if (this.hasDisconnected) {
                this.addSystemMessage('Reconnected to chat server');
            }
            
            // Reset reconnect attempts
            this.reconnectAttempts = 0;
            this.hasDisconnected = false;
            
            // Set connection status indicator
            this.updateConnectionStatus(true);
        });

        this.socket.on('disconnect', () => {
            console.log('Disconnected from chat server');
            this.addSystemMessage('Disconnected from chat server. Attempting to reconnect...');
            this.hasDisconnected = true;
            
            // Set connection status indicator
            this.updateConnectionStatus(false);
        });

        this.socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
            this.addSystemMessage('Connection error. Attempting to reconnect...');
            this.reconnectAttempts++;
            
            if (this.reconnectAttempts >= this.maxReconnectAttempts) {
                this.addSystemMessage('Failed to reconnect after multiple attempts. Please refresh the page.');
            }
            
            // Set connection status indicator
            this.updateConnectionStatus(false);
        });
        
        this.socket.on('reconnect', (attemptNumber) => {
            console.log(`Reconnected to chat server after ${attemptNumber} attempts`);
            this.updateConnectionStatus(true);
            this.addSystemMessage(`Reconnected to chat server after ${attemptNumber} attempts`);
            
            // Rejoin chat after reconnection
            if (this.socket.connected) {
                this.socket.emit('join_chat');
            }
        });
        
        this.socket.on('reconnect_error', (error) => {
            console.error('Reconnection error:', error);
            this.addSystemMessage('Reconnection failed. Please try refreshing the page.');
        });
        
        this.socket.on('reconnect_failed', () => {
            console.error('Reconnection failed after all attempts');
            this.addSystemMessage('Unable to reconnect. Please refresh the page.');
        });

        // Listen for new chat messages
        this.socket.on('new_chat_message', (data) => {
            // Check if this message is from another user
            // Only add messages from other users since our own messages are added locally
            if (data.user_id !== this.currentUserId) {
                console.log('Received message from:', data.username, 'Current user ID:', this.currentUserId);
                this.addMessage(data.username, data.message, data.created_at, false);
            }
        });

        // Listen for user join/leave notifications
        this.socket.on('user_joined_chat', (data) => {
            this.addSystemMessage(data.message);
        });

        this.socket.on('user_left_chat', (data) => {
            this.addSystemMessage(data.message);
        });
        
        // Add connection status indicator to the UI
        this.addConnectionStatusIndicator();
    }

    async loadMessages() {
        try {
            const response = await fetch('/api/chat/messages');
            const data = await response.json();
            
            if (data.error) {
                console.error('Error loading messages:', data.error);
                return;
            }
            
            this.messages = data.messages;
            
            // Get current user ID from the first own message
            const ownMessage = this.messages.find(m => m.is_own);
            if (ownMessage) {
                this.currentUserId = ownMessage.user_id;
                console.log('Current user ID set:', this.currentUserId);
            } else {
                // Try to get user ID from the page if available
                const userIdElement = document.getElementById('currentUserId');
                if (userIdElement) {
                    this.currentUserId = parseInt(userIdElement.value);
                    console.log('Current user ID set from page:', this.currentUserId);
                }
            }
            
            this.renderMessages();
            this.scrollToBottom();
            
        } catch (error) {
            console.error('Error loading messages:', error);
            this.showError('Failed to load messages');
        }
    }

    renderMessages() {
        const chatMessages = document.getElementById('chatMessages');
        
        if (this.messages.length === 0) {
            chatMessages.innerHTML = `
                <div class="no-messages">
                    <i class="fas fa-comments"></i>
                    <h3>No messages yet</h3>
                    <p>Be the first to start the conversation!</p>
                </div>
            `;
            return;
        }

        const messagesHTML = this.messages.map(message => this.createMessageHTML(message)).join('');
        chatMessages.innerHTML = messagesHTML;
    }

    createMessageHTML(message) {
        const isOwn = message.is_own;
        const messageClass = isOwn ? 'message own' : 'message';
        const avatarText = message.username.charAt(0).toUpperCase();
        const avatarClass = isOwn ? 'message-avatar own' : 'message-avatar';
        
        return `
            <div class="message ${messageClass}" data-message-id="${message.id}">
                <div class="${avatarClass}">
                    ${avatarText}
                </div>
                <div class="message-content">
                    <div class="message-header">
                        <span class="message-username">${this.escapeHtml(message.username)}</span>
                        <span class="message-time">${message.created_at}</span>
                    </div>
                    <div class="message-bubble">
                        <div class="message-text">${this.escapeHtml(message.message)}</div>
                    </div>
                </div>
            </div>
        `;
    }

    createSystemMessageHTML(message) {
        return `
            <div class="message system">
                <div class="message-content">
                    <div class="message-bubble">
                        <div class="message-text">${this.escapeHtml(message)}</div>
                    </div>
                </div>
            </div>
        `;
    }

    addMessage(username, message, timestamp, isOwn = false, tempId = null) {
        // Create message object
        const messageData = {
            id: tempId || Date.now() + Math.floor(Math.random() * 1000), // Use provided tempId or generate one
            username: username,
            message: message,
            created_at: timestamp || new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}),
            is_own: isOwn
        };
        
        // Check if message already exists (by content and username)
        // Use a more precise check to avoid duplicate messages
        const isDuplicate = this.messages.some(m => 
            m.username === messageData.username && 
            m.message === messageData.message && 
            Math.abs(new Date(m.created_at) - new Date(messageData.created_at)) < 5000 // Within 5 seconds
        );
        
        if (isDuplicate) {
            console.log('Duplicate message detected, not adding:', messageData);
            return;
        }

        // Add message to array
        this.messages.push(messageData);
        
        // Render the new message
        const chatMessages = document.getElementById('chatMessages');
        if (!chatMessages) {
            console.error('Chat messages container not found');
            return;
        }
        
        const messageHTML = this.createMessageHTML(messageData);
        
        // Remove loading state if it exists
        const loadingElement = chatMessages.querySelector('.loading-messages');
        if (loadingElement) {
            loadingElement.remove();
        }

        // Remove no messages state if it exists
        const noMessagesElement = chatMessages.querySelector('.no-messages');
        if (noMessagesElement) {
            noMessagesElement.remove();
        }

        chatMessages.insertAdjacentHTML('beforeend', messageHTML);
        
        // Scroll to bottom
        this.scrollToBottom();
        
        // Keep only last 100 messages for performance
        if (this.messages.length > 100) {
            this.messages = this.messages.slice(-100);
            this.renderMessages();
        }
    }

    addSystemMessage(message) {
        const chatMessages = document.getElementById('chatMessages');
        const messageHTML = this.createSystemMessageHTML(message);
        
        // Remove loading state if it exists
        const loadingElement = chatMessages.querySelector('.loading-messages');
        if (loadingElement) {
            loadingElement.remove();
        }
        
        // Remove no messages state if it exists
        const noMessagesElement = chatMessages.querySelector('.no-messages');
        if (noMessagesElement) {
            noMessagesElement.remove();
        }

        chatMessages.insertAdjacentHTML('beforeend', messageHTML);
        this.scrollToBottom();
    }

    async sendMessage() {
        const messageInput = document.getElementById('messageInput');
        if (!messageInput) {
            console.error('Message input element not found');
            return;
        }
        
        const message = messageInput.value.trim();
        if (!message) {
            return;
        }
        
        // Stop typing indicator
        this.stopTyping();

        // Store the message we're sending to track it
        const sentMessage = {
            text: message,
            timestamp: Date.now(),
            tempId: Date.now() + Math.floor(Math.random() * 1000)
        };
        
        // Get username from session or use a default
        const username = document.querySelector('.username')?.textContent || 'You';
        const timestamp = new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        
        try {
            // Add message locally first with the temporary ID
            this.addMessage(username, message, timestamp, true, sentMessage.tempId);
            
            // Clear input and update UI
            messageInput.value = '';
            this.updateCharCount();
            this.autoResizeTextarea();
            this.updateSendButtonState();
            
            // Send to server
            const response = await fetch('/api/chat/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message: message }),
                // Add timeout to prevent hanging requests
                signal: AbortSignal.timeout(10000) // 10 second timeout
            });

            // Handle HTTP errors
            if (!response.ok) {
                const errorText = await response.text();
                console.error(`Server error: ${response.status}`, errorText);
                throw new Error(`Server returned ${response.status}: ${response.statusText}`);
            }

            // Parse response data
            let data;
            try {
                data = await response.json();
            } catch (parseError) {
                console.error('Failed to parse server response:', parseError);
                throw new Error('Invalid server response');
            }
            
            // Handle API errors
            if (data.error) {
                console.error('API error:', data.error);
                this.showError(data.error);
                this.removeOptimisticMessage(sentMessage);
                return;
            }
            
            // Update the message with the server-provided ID if needed
            if (data.success && data.message && data.message.id) {
                // Find our optimistically added message and update its ID
                const messageIndex = this.messages.findIndex(m => 
                    m.is_own && m.message === sentMessage.text && 
                    (m.id === sentMessage.tempId || Math.abs(m.id - sentMessage.timestamp) < 5000)
                );
                
                if (messageIndex !== -1) {
                    this.messages[messageIndex].id = data.message.id;
                    console.log('Message sent successfully and updated with server ID:', data.message.id);
                }
            }
            
        } catch (error) {
            console.error('Error sending message:', error);
            this.showError('Failed to send message. Please try again.');
            this.removeOptimisticMessage(sentMessage);
        }
    }
    
    removeOptimisticMessage(sentMessage) {
        // Find and remove the optimistically added message
        const messageIndex = this.messages.findIndex(m => 
            m.is_own && m.message === sentMessage.text && 
            (m.id === sentMessage.tempId || Math.abs(m.id - sentMessage.timestamp) < 5000)
        );
        
        if (messageIndex !== -1) {
            this.messages.splice(messageIndex, 1);
            this.renderMessages(); // Re-render without the failed message
            console.log('Removed optimistic message after failure');
        }
    }

    handleInputChange(e) {
        const message = e.target.value;
        this.updateCharCount();
        this.updateSendButtonState();
        
        // Handle typing indicator
        if (message.trim().length > 0) {
            this.startTyping();
        } else {
            this.stopTyping();
        }
    }

    handleKeyDown(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            this.sendMessage();
        }
    }

    updateCharCount() {
        const messageInput = document.getElementById('messageInput');
        const charCount = document.getElementById('charCount');
        const currentLength = messageInput.value.length;
        const maxLength = 500;
        
        charCount.textContent = `${currentLength}/${maxLength}`;
        
        // Change color based on length
        if (currentLength > maxLength * 0.9) {
            charCount.style.color = 'var(--accent-warning)';
        } else if (currentLength > maxLength * 0.8) {
            charCount.style.color = 'var(--accent-danger)';
        } else {
            charCount.style.color = 'var(--text-muted)';
        }
    }

    updateSendButtonState() {
        const messageInput = document.getElementById('messageInput');
        const sendBtn = document.getElementById('sendBtn');
        
        if (messageInput && sendBtn) {
            const message = messageInput.value.trim();
            sendBtn.disabled = !message;
            
            // Update button appearance based on state
            if (message) {
                sendBtn.classList.add('active');
            } else {
                sendBtn.classList.remove('active');
            }
        }
    }

    autoResizeTextarea() {
        const messageInput = document.getElementById('messageInput');
        messageInput.style.height = 'auto';
        messageInput.style.height = Math.min(messageInput.scrollHeight, 120) + 'px';
    }

    scrollToBottom() {
        const chatMessages = document.getElementById('chatMessages');
        if (!chatMessages) {
            console.error('Chat messages container not found');
            return;
        }
        
        // Use smooth scrolling with a small delay to ensure all content is rendered
        setTimeout(() => {
            chatMessages.scrollTo({
                top: chatMessages.scrollHeight,
                behavior: 'smooth'
            });
        }, 50);
    }

    showError(message) {
        // Check if an error with the same message already exists
        const existingErrors = document.querySelectorAll('.error-notification');
        for (const error of existingErrors) {
            if (error.querySelector('span')?.textContent === message) {
                // Reset the removal timeout for this error
                if (error.dataset.timeoutId) {
                    clearTimeout(parseInt(error.dataset.timeoutId));
                }
                
                // Set new timeout
                const timeoutId = setTimeout(() => {
                    if (error.parentNode) {
                        error.remove();
                    }
                }, 5000);
                error.dataset.timeoutId = timeoutId.toString();
                return;
            }
        }
        
        // Create error notification
        const notification = document.createElement('div');
        notification.className = 'error-notification';
        notification.innerHTML = `
            <i class="fas fa-exclamation-circle"></i>
            <span>${message}</span>
        `;
        
        // Add styles
        notification.style.cssText = `
            position: fixed;
            top: 100px;
            right: 20px;
            background: var(--accent-danger);
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 0.5rem;
            box-shadow: var(--shadow-lg);
            z-index: 10000;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            animation: slideInRight 0.3s ease-out;
            max-width: 300px;
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        const timeoutId = setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
        notification.dataset.timeoutId = timeoutId.toString();
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    // Connection status methods
    addConnectionStatusIndicator() {
        const chatContainer = document.querySelector('.chat-container');
        if (!chatContainer) {
            console.error('Chat container not found');
            return;
        }
        
        // Check if status indicator already exists
        let statusElement = document.querySelector('.connection-status');
        if (!statusElement) {
            statusElement = document.createElement('div');
            statusElement.className = 'connection-status';
            statusElement.innerHTML = `
                <div class="status-indicator"></div>
                <span class="status-text">Disconnected</span>
            `;
            chatContainer.appendChild(statusElement);
        }
        
        // Initially show as disconnected
        this.updateConnectionStatus(this.socket && this.socket.connected);
    }
    
    updateConnectionStatus(isConnected) {
        const statusIndicator = document.querySelector('.connection-status .status-indicator');
        const statusText = document.querySelector('.connection-status .status-text');
        
        if (!statusIndicator || !statusText) {
            console.error('Connection status elements not found');
            return;
        }
        
        if (isConnected) {
            statusIndicator.classList.add('connected');
            statusText.textContent = 'Connected';
        } else {
            statusIndicator.classList.remove('connected');
            statusText.textContent = 'Disconnected';
        }
    }
    
    // Typing indicator methods
    setupTypingIndicator() {
        // Create typing indicator element
        const chatMessages = document.getElementById('chatMessages');
        if (!chatMessages) {
            console.error('Chat messages container not found');
            return;
        }
        
        // Check if typing indicator already exists
        let typingIndicator = document.querySelector('.typing-indicator');
        if (!typingIndicator) {
            typingIndicator = document.createElement('div');
            typingIndicator.className = 'typing-indicator';
            typingIndicator.style.display = 'none';
            typingIndicator.innerHTML = `
                <span>Someone is typing</span>
                <div class="dots">
                    <div class="dot"></div>
                    <div class="dot"></div>
                    <div class="dot"></div>
                </div>
            `;
            chatMessages.parentNode.insertBefore(typingIndicator, chatMessages.nextSibling);
        }
        
        // Listen for typing events from other users
        this.socket.on('user_typing', (data) => {
            if (data.userId !== this.currentUserId) {
                this.showTypingIndicator(data.username || 'Someone');
            }
        });
        
        this.socket.on('user_stopped_typing', (data) => {
            if (data.userId !== this.currentUserId) {
                this.hideTypingIndicator();
            }
        });
    }
    
    startTyping() {
        if (!this.isTyping) {
            this.isTyping = true;
            if (this.socket && this.socket.connected) {
                this.socket.emit('typing');
            }
            
            // Reset typing timeout
            clearTimeout(this.typingTimeout);
            this.typingTimeout = setTimeout(() => {
                this.stopTyping();
            }, 3000); // Stop typing after 3 seconds of inactivity
        } else {
            // Reset typing timeout
            clearTimeout(this.typingTimeout);
            this.typingTimeout = setTimeout(() => {
                this.stopTyping();
            }, 3000);
        }
    }
    
    stopTyping() {
        if (this.isTyping) {
            this.isTyping = false;
            if (this.socket && this.socket.connected) {
                this.socket.emit('stop_typing');
            }
            clearTimeout(this.typingTimeout);
        }
    }
    
    showTypingIndicator(username) {
        const typingIndicator = document.querySelector('.typing-indicator');
        if (!typingIndicator) {
            console.error('Typing indicator element not found');
            return;
        }
        
        const usernameSpan = typingIndicator.querySelector('span');
        if (usernameSpan) {
            usernameSpan.textContent = `${username} is typing`;
        }
        typingIndicator.style.display = 'flex';
        
        // Auto-hide after 5 seconds in case we don't receive a stop_typing event
        clearTimeout(this.hideTypingTimeout);
        this.hideTypingTimeout = setTimeout(() => {
            this.hideTypingIndicator();
        }, 5000);
        
        this.scrollToBottom();
    }
    
    hideTypingIndicator() {
        const typingIndicator = document.querySelector('.typing-indicator');
        if (typingIndicator) {
            typingIndicator.style.display = 'none';
        }
        clearTimeout(this.hideTypingTimeout);
    }
}

// Initialize chat system when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.chatSystem = new ChatSystem();
});

// Add some CSS for error notifications and connection status
const style = document.createElement('style');
style.textContent = `
    .error-notification {
        font-family: 'Inter', sans-serif;
        font-weight: 500;
    }
    
    .no-messages {
        text-align: center;
        padding: 3rem 1rem;
        color: var(--text-muted);
    }
    
    .no-messages i {
        font-size: 3rem;
        margin-bottom: 1rem;
        opacity: 0.5;
    }
    
    .no-messages h3 {
        font-size: 1.25rem;
        margin-bottom: 0.5rem;
        color: var(--text-secondary);
    }
    
    .no-messages p {
        font-size: 0.875rem;
        opacity: 0.8;
    }
    
    .connection-status {
        position: absolute;
        top: 10px;
        right: 10px;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.75rem;
        color: var(--text-secondary);
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        background-color: var(--bg-tertiary);
        z-index: 100;
    }
    
    .connection-status .status-indicator {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: var(--accent-danger);
    }
    
    .connection-status .status-indicator.connected {
        background-color: var(--accent-success);
    }
    
    .message.system {
        margin: 0.5rem 0;
        text-align: center;
    }
    
    .message.system .message-bubble {
        display: inline-block;
        background-color: var(--bg-tertiary);
        color: var(--text-secondary);
        font-size: 0.75rem;
        padding: 0.25rem 0.75rem;
        border-radius: 1rem;
        max-width: 80%;
    }
    
    .typing-indicator {
        display: flex;
        align-items: center;
        gap: 0.25rem;
        padding: 0.5rem 1rem;
        color: var(--text-secondary);
        font-size: 0.75rem;
    }
    
    .typing-indicator .dots {
        display: flex;
        gap: 0.25rem;
    }
    
    .typing-indicator .dot {
        width: 4px;
        height: 4px;
        border-radius: 50%;
        background-color: var(--text-secondary);
        animation: typingAnimation 1.5s infinite ease-in-out;
    }
    
    .typing-indicator .dot:nth-child(2) {
        animation-delay: 0.2s;
    }
    
    .typing-indicator .dot:nth-child(3) {
        animation-delay: 0.4s;
    }
    
    @keyframes typingAnimation {
        0%, 60%, 100% {
            transform: translateY(0);
            opacity: 0.6;
        }
        30% {
            transform: translateY(-4px);
            opacity: 1;
        }
    }
`;
document.head.appendChild(style);
