-- Create ChatMessage table for the CTF game chat system
CREATE TABLE IF NOT EXISTS chat_message (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

-- Add index for better performance
CREATE INDEX idx_chat_message_created_at ON chat_message(created_at);
CREATE INDEX idx_chat_message_user_id ON chat_message(user_id);

-- Insert some sample messages for testing (optional)
-- INSERT INTO chat_message (user_id, message) VALUES 
-- (1, 'Welcome to HUNTING-CTF! Let\'s solve some challenges together!'),
-- (1, 'Feel free to ask questions and collaborate with other players.');
