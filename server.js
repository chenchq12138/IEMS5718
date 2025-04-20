const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const multer = require('multer');
const sharp = require('sharp');
const fs = require('fs');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');

const server = express();
const upload = multer({ dest: 'public/images/' });
server.use(bodyParser.urlencoded({ extended: true }));
server.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
server.set('views', path.join(__dirname, 'views'));
server.set('view engine', 'ejs');
server.use(express.static(path.join(__dirname, 'public')));
server.use(express.json());

function setUserStatus(req, res, next) {
    // 假设用户信息存储在会话中
    const user = req.session.user || null;

    // 设置用户状态
    res.locals.user = {
        isLoggedIn: !!user, // 判断是否有用户信息
        name: user ? user.user_name : null, // 用户名
        userid: user ? user.userid : null,  // 用户 ID（如果需要）
        admin: user ? user.admin : false   // 管理员状态
    };

    next();
}

// 定义 generateAuthToken 函数
function generateAuthToken(user) {
    const payload = {
        userid: user.userid,
        email: user.email,
        user_name: user.user_name
    };
    const secretKey = '1155224919'; // 替换为你的密钥
    const options = { expiresIn: '1h' }; // 设置过期时间

    return jwt.sign(payload, secretKey, options);
}

// 在应用中使用中间件
server.use(setUserStatus);

// Session Configuration
server.use(session({
    secret: '1155224919',
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000,
    },
}));

// Nonce and CSP Middleware
server.use((req, res, next) => {
    const nonce = Math.random().toString(36).substring(2, 15);
    res.locals.nonce = nonce;

    res.setHeader(
        "Content-Security-Policy",
        `default-src 'self'; script-src 'self' https://apis.google.com 'nonce-${nonce}'; object-src 'none'; frame-ancestors 'self';`
    );
    next();
});

// CSRF Token Middleware
server.use((req, res, next) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = Math.random().toString(36).substring(7);
    }
    res.locals.csrfToken = req.session.csrfToken;
    next();
});

// 连接数据库
const mysql = require('mysql2/promise');
const pool = mysql.createPool({
    host: '58.176.220.19',
    user: 'test_user',
    password: '123456',
    database: 'shopping_database'
});
// 使用异步函数测试数据库连接
async function testDatabaseConnection() {
    try {
        // 获取连接
        const conn = await pool.getConnection();
        try {
            console.log('Connected to MySQL database.');
        } finally {
            // 释放连接回到连接池
            conn.release();
        }
    } catch (err) {
        console.error('Error connecting to the database:', err);
    }
}
testDatabaseConnection();

// 连接成功
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// demo
server.get('/demo', (req, res) => {
    res.render('demo');
});

// 登录界面
server.get('/login', async (req, res) => {
    res.render('login');
});

// 主界面
server.get('/', async (req, res) => {
    try {
        // 获取分类数据
        const [categoriesResult] = await pool.execute('SELECT * FROM categories');
        const categories = categoriesResult;

        // 获取商品数据
        const [productsResult] = await pool.execute('SELECT * FROM products');
        const products = productsResult;

        // 渲染页面
        res.render('main', { categories, products });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).send('Internal Server Error');
    }
});

// category界面
server.get('/category/:id', async (req, res) => {
    const categoryId = req.params.id;

    try {
        // 获取分类信息
        const [categoriesResult] = await pool.execute('SELECT * FROM categories WHERE catid = ?', [categoryId]);
        if (categoriesResult.length === 0) {
            return res.status(404).send('Category not found');
        }
        const category = categoriesResult[0];

        // 获取该分类下的商品信息
        const [productsResult] = await pool.execute('SELECT * FROM products WHERE catid = ?', [categoryId]);
        const products = productsResult;

        // 渲染页面
        res.render('categoryDetails', { category, products });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).send('Internal Server Error');
    }
});

// product界面
server.get('/product/:id', async (req, res) => {
    const productId = req.params.id;

    try {
        // 获取商品信息
        const [productsResult] = await pool.execute('SELECT * FROM products WHERE pid = ?', [productId]);
        if (productsResult.length === 0) {
            return res.status(404).send('Product not found');
        }
        const product = productsResult[0];

        // 获取商品所属分类信息
        const [categoriesResult] = await pool.execute('SELECT * FROM categories WHERE catid = ?', [product.catid]);
        if (categoriesResult.length === 0) {
            return res.status(404).send('Category not found');
        }
        const category = categoriesResult[0];

        // 渲染页面
        res.render('productDetails', { category, product });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).send('Internal Server Error');
    }
});

// 管理界面
server.get('/admin', async (req, res) => {
    try {
        // 获取所有分类信息
        const [categoriesResult] = await pool.execute('SELECT * FROM categories');

        // 获取所有商品信息
        const [productsResult] = await pool.execute('SELECT * FROM products');

        // 渲染页面
        res.render('adminpanel', { categories: categoriesResult, products: productsResult });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).send('Internal Server Error');
    }
});

// 跳转到修改product界面
server.get('/change-product-view/:id', async (req, res) => {
    const productId = req.params.id;

    try {
        // 获取商品信息
        const [productsResult] = await pool.execute('SELECT * FROM products WHERE pid = ?', [productId]);
        if (productsResult.length === 0) {
            return res.status(404).send('Product not found');
        }
        const product = productsResult[0];

        // 获取所有分类信息
        const [categoriesResult] = await pool.execute('SELECT * FROM categories');
        const categories = categoriesResult;

        // 渲染页面
        res.render('change_product', { categories, product });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).send('Internal Server Error');
    }
});

// 跳转到增加product界面
server.get('/add-product-view/:id', async (req, res) => {
    const categoryId = req.params.id;

    try {
        // 获取所有分类信息
        const [categoriesResult] = await pool.execute('SELECT * FROM categories');
        const categories = categoriesResult;

        // 渲染页面
        res.render('add_product', { categoryId, categories });
    } catch (error) {
        console.error('Error fetching categories:', error);
        res.status(500).send('Internal Server Error');
    }
});

// 删除product
server.post('/delete-product', async (req, res) => {
    const submittedToken = req.body.csrfToken;
    const sessionToken = req.session.csrfToken;
    if (!submittedToken || submittedToken !== sessionToken) {
        return res.status(403).send('CSRF token validation failed');
    }

    const productId = req.body.productId;

    try {
        // 删除商品记录
        const [results] = await pool.execute('DELETE FROM products WHERE pid = ?', [productId]);
        if (results.affectedRows === 0) {
            return res.status(404).json({ message: 'Product not found' });
        }

        // 删除商品图片
        const imagePaths = [
            path.join(__dirname, '/public/images/', `${productId}.png`),
            path.join(__dirname, '/public/images/', `${productId}-thumb.png`)
        ];

        for (const imagePath of imagePaths) {
            try {
                await fs.promises.unlink(imagePath); // 使用 Promise 版本的 unlink
            } catch (err) {
                if (err.code !== 'ENOENT') {
                    console.error('Failed to delete image:', err);
                }
            }
        }

        res.status(200).json({ message: `Product with ID ${productId} deleted successfully` });
    } catch (error) {
        console.error('Error deleting product:', error);
        res.status(500).json({ error: 'Error deleting product' });
    }
});

// 删除文件的函数，带有重试机制
function deleteFileWithRetry(filePath, retries = 3, delay = 1000) {
    return new Promise((resolve, reject) => {
        const attemptDelete = () => {
            fs.unlink(filePath, (err) => {
                if (err) {
                    if (retries > 0) {
                        console.warn(`Failed to delete file ${filePath}, retrying... (${retries} retries left)`);
                        retries--;
                        setTimeout(attemptDelete, delay);
                    } else {
                        console.error(`Failed to delete file after multiple attempts: ${filePath}`);
                        reject(err);
                    }
                } else {
                    resolve();
                }
            });
        };
        attemptDelete();
    });
}

//添加product
server.post('/add-product', upload.single('image'), async (req, res) => {
    const submittedToken = req.body.csrfToken;
    const sessionToken = req.session.csrfToken;
    if (!submittedToken || submittedToken !== sessionToken) {
        return res.status(403).send('CSRF token validation failed');
    }

    try {
        const catid = req.body.catid;
        const name = req.body.name;
        const price = req.body.price;
        const description = req.body.description;

        // 简单验证输入数据
        if (!catid || !name || !price || !description || !req.file) {
            return res.status(400).json({ success: false, message: 'All fields are required.' });
        }

        // 开始事务
        await pool.query('START TRANSACTION');

        try {
            // 插入产品信息到数据库
            const [result] = await pool.execute(
                'INSERT INTO products (catid, name, price, description) VALUES (?, ?, ?, ?)',
                [catid, name, price, description]
            );

            const pid = result.insertId;

            // 确保 images 文件夹存在
            const imagesDir = path.join(__dirname, 'public', 'images');
            if (!fs.existsSync(imagesDir)) {
                fs.mkdirSync(imagesDir, { recursive: true });
            }

            // 新图片路径和缩略图路径
            const newImagePath = path.join(imagesDir, `${pid}.png`);
            const thumbImagePath = path.join(imagesDir, `${pid}-thumb.png`);

            // 使用 sharp 处理图片并生成缩略图
            await sharp(req.file.path)
                .resize(300, 300)
                .toFile(thumbImagePath);

            // 将原始图片转换为 PNG 格式并保存
            await sharp(req.file.path)
                .toFormat('png')
                .toFile(newImagePath);

            // 删除临时上传的文件
            try {
                await deleteFileWithRetry(req.file.path);
            } catch (unlinkErr) {
                console.error('Error deleting temporary file:', unlinkErr);
            }

            // 提交事务
            await pool.query('COMMIT');
            res.status(200).json({ success: true, message: 'Product added successfully!', pid });
        } catch (error) {
            // 出现错误时回滚事务
            await pool.query('ROLLBACK');
            console.error(error);
            res.status(500).send('An error occurred while adding the product.');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('An error occurred during the process.');
    }
});

// 修改product
server.post('/change-product', upload.single('image'), async (req, res) => {
    const submittedToken = req.body.csrfToken;
    const sessionToken = req.session.csrfToken;
    if (!submittedToken || submittedToken !== sessionToken) {
        return res.status(403).send('CSRF token validation failed');
    }
    try {
        const productId = req.body.productId;
        const updates = {};

        if (!productId) {
            return res.status(400).json({ success: false, message: 'productId is required.' });
        }

        // 检查每个字段是否有新值
        ['catid', 'name', 'price', 'description'].forEach(field => {
            if (req.body[field]) {
                updates[field] = req.body[field];
            }
        });

        // 开始事务
        await pool.query('START TRANSACTION');

        try {
            if (Object.keys(updates).length > 0) {
                const updateQuery = 'UPDATE products SET ' + Object.keys(updates).map(key => `${key} = ?`).join(', ') + ' WHERE pid = ?';
                const params = [...Object.values(updates), productId];
                await pool.execute(updateQuery, params);
            }

            const imagesDir = path.join(__dirname, 'public', 'images');

            if (req.file) { // 如果上传了新图片
                // 确保 images 文件夹存在
                if (!fs.existsSync(imagesDir)) {
                    fs.mkdirSync(imagesDir, { recursive: true });
                }

                // 新图片路径和缩略图路径
                const newImagePath = path.join(imagesDir, `${productId}.png`);
                const thumbImagePath = path.join(imagesDir, `${productId}-thumb.png`);

                // 使用 sharp 处理图片并生成缩略图
                await sharp(req.file.path)
                    .resize(300, 300)
                    .toFile(thumbImagePath);

                // 将原始图片转换为 PNG 格式并保存
                await sharp(req.file.path)
                    .toFormat('png')
                    .toFile(newImagePath);

                // 删除临时上传的文件
                try {
                    await deleteFileWithRetry(req.file.path);
                } catch (unlinkErr) {
                    console.error('Error deleting temporary file:', unlinkErr);
                }
            }

            // 提交事务
            await pool.query('COMMIT');
            res.status(200).json({ success: true, message: 'Product changed successfully!' });
        } catch (error) {
            // 出现错误时回滚事务
            await pool.query('ROLLBACK');
            console.error(error);
            res.status(500).send('An error occurred while updating the product.');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('An error occurred during the process.');
    }
});

// async function getUserCart(userId) {
//     const conn = await connection.getConnection();
//     try {
//         const [rows] = await conn.query(`
//             SELECT p.name, ci.quantity, ci.id 
//             FROM cartItems ci 
//             JOIN products p ON ci.pid = p.pid 
//             WHERE ci.userid = ?`, [userId]);
//         return rows;
//     } finally {
//         conn.release();
//     }
// }

server.get('/get-cart', async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection(); // 从连接池中获取连接
        // 使用参数化查询（虽然这里没有动态参数，但仍使用 query 方法）
        const [rows] = await conn.execute(`
            SELECT ci.id AS cartItemId, p.pid, p.name, p.price, ci.quantity 
            FROM cartItems ci 
            JOIN products p ON ci.pid = p.pid
        `);
        res.json({ cartItems: rows });
    } catch (error) {
        console.error('Error fetching cart items:', error);
        res.status(500).json({ error: 'Failed to fetch cart items' });
    } finally {
        if (conn) conn.release(); // 确保释放连接
    }
});

server.post('/update-cart', express.json(), async (req, res) => {
    const submittedToken = req.body.csrfToken;
    const sessionToken = req.session.csrfToken;
    if (!submittedToken || submittedToken !== sessionToken) {
        return res.status(403).send('CSRF token validation failed');
    }
    const { productId } = req.body;

    let conn;
    try {
        conn = await pool.getConnection(); // 从连接池中获取连接

        // 查询产品价格
        const [product] = await conn.execute('SELECT price FROM products WHERE pid = ?', [productId]);
        if (product.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        const productPrice = product[0].price;

        // 检查商品是否已经在购物车中
        const [existingCartItem] = await conn.execute('SELECT id FROM cartItems WHERE pid = ?', [productId]);
        if (existingCartItem.length > 0) {
            // 如果存在，则增加数量
            await conn.execute('UPDATE cartItems SET quantity = quantity + 1 WHERE pid = ?', [productId]);
        } else {
            // 如果不存在，则插入新条目
            await conn.execute('INSERT INTO cartItems (pid, quantity, userid, price) VALUES (?, 1, 1, ?)', [productId, productPrice]);
        }

        res.json({ success: true, message: 'Product added to cart.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to add product to cart' });
    } finally {
        if (conn) conn.release(); // 确保释放连接
    }
});

server.post('/update-cart-item', express.json(), async (req, res) => {
    const submittedToken = req.body.csrfToken;
    const sessionToken = req.session.csrfToken;
    if (!submittedToken || submittedToken !== sessionToken) {
        return res.status(403).send('CSRF token validation failed');
    }
    const { itemId, quantity } = req.body;

    let conn;
    try {
        conn = await pool.getConnection(); // 从连接池中获取连接
        await conn.execute('UPDATE cartItems SET quantity = ? WHERE id = ?', [quantity, itemId]);
        res.json({ success: true, message: 'Cart item updated.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to update cart item' });
    } finally {
        if (conn) conn.release(); // 确保释放连接
    }
});

server.delete('/remove-from-cart/:itemId', async (req, res) => {
    // 从请求头中获取 CSRF Token
    const submittedToken = req.headers['x-csrf-token'];
    const sessionToken = req.session.csrfToken;

    if (!submittedToken || submittedToken !== sessionToken) {
        return res.status(403).send('CSRF token validation failed');
    }
    const itemId = req.params.itemId;

    let conn;
    try {
        conn = await pool.getConnection(); // 从连接池中获取连接
        await conn.execute('DELETE FROM cartItems WHERE id = ?', [itemId]);
        res.json({ success: true, message: 'Item removed from cart.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to remove item from cart' });
    } finally {
        if (conn) conn.release(); // 确保释放连接
    }
});

// 加密密码
async function hashPassword(password) {
    const salt = await bcrypt.genSalt(saltRounds);
    return await bcrypt.hash(password, salt);
}

server.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

    if (rows.length > 0) {
        const user = rows[0];
        const match = await bcrypt.compare(password, user.password);

        if (match) {
            // 将用户信息存储到 session
            req.session.user = {
                userid: user.userid,
                email: user.email,
                user_name: user.user_name,
                admin: user.admin
            };

            // 成功登录后的操作
            const token = generateAuthToken(user); // 假设这是生成token的函数
            res.cookie('authToken', token, { 
                httpOnly: true, 
                secure: process.env.NODE_ENV === 'production', 
                maxAge: 3 * 24 * 60 * 60 * 1000 
            });

            // 重定向
            return res.redirect(user.admin ? '/admin' : '/');
        }
    }

    // 登录失败
    res.render('login', { error: 'Invalid email or password.' });
});

server.post('/signup', async (req, res) => {
    const { email, password, user_name } = req.body;

    if (!email || !password || !user_name) {
        return res.status(400).json({ error: "Email and password are required." });
    }

    try {
        // 检查用户是否已存在
        const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length > 0) {
            return res.status(400).json({ error: "User already exists." });
        }

        // 对密码进行加盐哈希
        const hashedPassword = await hashPassword(password);

        // 插入新用户
        await pool.query(
            'INSERT INTO users (email, password, admin, user_name) VALUES (?, ?, ?, ?)',
            [email, hashedPassword, false, user_name]
        );

        res.render('login');
    } catch (error) {
        console.error("Error registering user:", error);
        res.status(500).json({ error: "Internal server error." });
    }
});

server.get('/logout', (req, res) => {
    // 销毁会话
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ message: 'Logout failed.' });
        }
        res.clearCookie('authToken'); // 假设你使用名为 authToken 的 Cookie

        res.render('login');
    });
});