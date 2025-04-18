CREATE USER test_user@'%' IDENTIFIED BY '123456';
GRANT ALL PRIVILEGES ON shopping_database.* TO test_user@'%';

CREATE DATABASE shopping_database;

USE shopping_database;

CREATE TABLE categories (
    catid INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL
);

CREATE TABLE products (
    pid INT AUTO_INCREMENT PRIMARY KEY,
    catid INT,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10, 2),
    description TEXT,
    FOREIGN KEY (catid) REFERENCES categories(catid)
);

CREATE TABLE users (
    userid INT AUTO_INCREMENT PRIMARY KEY,
    user_name VARCHAR(255) DEFAULT '',
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    admin BOOLEAN DEFAULT FALSE
);

CREATE TABLE cartItems (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userid INT NOT NULL, 
    pid INT NOT NULL, 
    price INT NOT NULL,
    quantity INT NOT NULL DEFAULT 1, 
    FOREIGN KEY (pid) REFERENCES products(pid),
    FOREIGN KEY (userid) REFERENCES users(userid)
);

INSERT INTO categories (name) VALUES ('Shoes'), ('Clothes');

INSERT INTO products (catid, name, price, description) VALUES 
(1, 'Jordan Air Jordan 1 low se washed denim', 599, 'Air Jordan 1 low se washed denim draws design inspiration from the original model released in 1985, featuring a simple and elegant classic appearance with a touch of novelty amidst familiarity. This shoe features a classic design that is comfortable and versatile, helping you showcase your outstanding style.'),
(1, 'Jordan Air Jordan 1 mid se', 609, 'Jordan Air Jordan 1 mid se has been reinterpreted, injecting vitality into its neutral color scheme design. High quality smooth leather combined with classic Nike Air cushioning configuration creates Jordans outstanding quality and comfortable foot feel as always.');

INSERT INTO users (user_name, email, password, admin) VALUES ('CHEN Chaoqun', '1155224919@gmail.com', '$2b$10$LyYzjtwVNobZmPku.ilTXediXBf9pbbOvrK5atm0HQcfNGCeeDcfy', true);