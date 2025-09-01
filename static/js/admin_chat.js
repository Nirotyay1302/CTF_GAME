// Admin Chat Monitoring JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize chat monitoring
    loadChatMessages();
    
    // Set up refresh interval (every 10 seconds)
    setInterval(loadChatMessages, 10000);
    
    // Set up event listeners
    document.getElementById('refresh-chat').addEventListener('click', loadChatMessages);
    document.getElementById('clear-chat').addEventListener('click', clearChatHistory);
    document.getElementById('search-messages').addEventListener('input', filterMessages);
    document.getElementById('save-moderation').addEventListener('click', saveModeration);
});

/**
 * Load chat messages from the server
 */
function loadChatMessages() {
    fetch('/api/admin/chat/messages')
        .then(response => response.json())
        .then(data => {
            updateChatStatistics(data);
            updateChatMessages(data.messages);
        })
        .catch(error => {
            console.error('Error loading chat messages:', error);
        });
}

/**
 * Update chat statistics display
 */
function updateChatStatistics(data) {
    document.getElementById('total-messages').textContent = data.total_messages;
    document.getElementById('active-users').textContent = data.active_users;
    document.getElementById('today-messages').textContent = data.today_messages;
}

/**
 * Update chat messages display
 */
function updateChatMessages(messages) {
    const chatContainer = document.getElementById('chat-messages');
    const searchTerm = document.getElementById('search-messages').value.toLowerCase();
    
    // Clear existing messages if not searching
    if (!searchTerm) {
        chatContainer.innerHTML = '';
    }
    
    // Add messages to the container
    messages.forEach(message => {
        // Skip if filtering and message doesn't match
        if (searchTerm && !message.content.toLowerCase().includes(searchTerm) && 
            !message.username.toLowerCase().includes(searchTerm)) {
            return;
        }
        
        const messageElement = document.createElement('div');
        messageElement.className = 'message';
        messageElement.dataset.id = message.id;
        
        const timestamp = new Date(message.created_at).toLocaleString();
        
        messageElement.innerHTML = `
            <div class="message-header">
                <span class="username">${message.username}</span>
                <span class="timestamp">${timestamp}</span>
                <span class="room">${message.room}</span>
            </div>
            <div class="message-content">${message.content}</div>
            <div class="message-actions">
                <button class="delete-message" onclick="deleteMessage(${message.id})">Delete</button>
                <button class="warn-user" onclick="warnUser(${message.user_id})">Warn User</button>
            </div>
        `;
        
        chatContainer.appendChild(messageElement);
    });
}

/**
 * Filter messages based on search term
 */
function filterMessages() {
    const searchTerm = document.getElementById('search-messages').value.toLowerCase();
    const messages = document.querySelectorAll('#chat-messages .message');
    
    messages.forEach(message => {
        const content = message.querySelector('.message-content').textContent.toLowerCase();
        const username = message.querySelector('.username').textContent.toLowerCase();
        
        if (content.includes(searchTerm) || username.includes(searchTerm)) {
            message.style.display = 'block';
        } else {
            message.style.display = 'none';
        }
    });
}

/**
 * Clear chat history
 */
function clearChatHistory() {
    if (!confirm('Are you sure you want to clear all public chat messages? This action cannot be undone.')) {
        return;
    }
    
    fetch('/api/chat/clear', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Reload messages
            loadChatMessages();
            showNotification('Chat history cleared successfully', 'success');
        } else {
            showNotification('Failed to clear chat history: ' + data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error clearing chat history:', error);
        showNotification('Failed to clear chat history', 'error');
    });
}

/**
 * Delete a specific message
 */
function deleteMessage(messageId) {
    fetch(`/api/chat/delete/${messageId}`, {
        method: 'DELETE'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Remove message from DOM
            const messageElement = document.querySelector(`.message[data-id="${messageId}"]`);
            if (messageElement) {
                messageElement.remove();
            }
            showNotification('Message deleted successfully', 'success');
        } else {
            showNotification('Failed to delete message: ' + data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error deleting message:', error);
        showNotification('Failed to delete message', 'error');
    });
}

/**
 * Warn a user (placeholder function)
 */
function warnUser(userId) {
    // This would be implemented in a real system
    alert(`Warning sent to user ID: ${userId}`);
}

/**
 * Save moderation settings
 */
function saveModeration() {
    const bannedWordsText = document.getElementById('banned-words').value;
    const bannedWords = bannedWordsText.split('\n').filter(word => word.trim() !== '');
    const autoModerate = document.getElementById('auto-moderate').checked;
    
    fetch('/api/admin/chat/moderation', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            banned_words: bannedWords,
            auto_moderate: autoModerate
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Moderation settings saved successfully', 'success');
        } else {
            showNotification('Failed to save moderation settings: ' + data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error saving moderation settings:', error);
        showNotification('Failed to save moderation settings', 'error');
    });
}

/**
 * Show a notification message
 */
function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Remove notification after 3 seconds
    setTimeout(() => {
        notification.remove();
    }, 3000);
}