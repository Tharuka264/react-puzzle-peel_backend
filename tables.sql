CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY, 
    email VARCHAR(255) NOT NULL UNIQUE, 
    username VARCHAR(100) NOT NULL, 
    password VARCHAR(255) NOT NULL, 
    highest_score INT DEFAULT 0
);