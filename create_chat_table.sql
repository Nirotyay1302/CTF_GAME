-- Create ChatMessage table for the CTF game chat system
CREATE TABLE IF NOT EXISTS chat_message (
    id INT AUTO_INCREMENT PRIMARY KEY,
    channel_id INT NOT NULL,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    message_type VARCHAR(20),
    timestamp DATETIME,
    edited BOOLEAN DEFAULT FALSE,
    edited_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Add foreign keys
ALTER TABLE chat_message ADD FOREIGN KEY (channel_id) REFERENCES chat_channel(id) ON DELETE CASCADE;
ALTER TABLE chat_message ADD FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE;
    edited BOOLEAN DEFAULT FALSE,
    edited_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Add foreign keys
ALTER TABLE chat_message ADD FOREIGN KEY (channel_id) REFERENCES chat_channel(id) ON DELETE CASCADE;
ALTER TABLE chat_message ADD FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE;

-- Add index for better performance
CREATE INDEX idx_chat_message_created_at ON chat_message(created_at);
CREATE INDEX idx_chat_message_user_id ON chat_message(user_id);

