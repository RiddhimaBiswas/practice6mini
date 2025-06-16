const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');

const UserModel = require('./model/user');
const PostModel = require('./model/post');

const app = express();

// Middleware setup
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Serve uploads statically from 'public/uploads'
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

// Create uploads directory if missing
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log('Created uploads directory:', uploadDir);
}

// MongoDB connection
mongoose.connect('mongodb://127.0.0.1:27017/miniproject', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err.stack));

// Multer storage config for uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png/;
    const extname = allowed.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowed.test(file.mimetype);
    if (extname && mimetype) cb(null, true);
    else cb(new Error('Only JPEG/PNG images allowed'));
  },
});

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'shhhha-string-secret-at-least-256-bits-long';

// Auth middleware
function ensureAuthenticated(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.clearCookie('token');
    return res.redirect('/login');
  }
}

// Routes

// Home page shows posts and uploads images
app.get('/', ensureAuthenticated, async (req, res) => {
  try {
    // Read files in uploads folder for images
    const files = await fs.promises.readdir(uploadDir);
    const images = files
      .filter(f => /\.(jpg|jpeg|png|gif|webp)$/i.test(f))
      .map(f => `/uploads/${f}`);

    // Fetch posts with user info populated
    const posts = await PostModel.find().populate('user').lean();

    res.render('index', { posts, user: req.user, uploadImages: images });
  } catch (err) {
    console.error('Error loading home page:', err);
    res.render('index', { posts: [], user: req.user, uploadImages: [] });
  }
});

app.get('/login', (req, res) => res.render('login', { error: null }));
app.get('/register', (req, res) => res.render('register', { error: null }));

app.post('/register', async (req, res) => {
  try {
    const { username, name, age, email, password } = req.body;
    const existingUser = await UserModel.findOne({ email }).lean();
    if (existingUser) {
      return res.status(400).render('register', { error: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await UserModel.create({ username, name, age, email, password: hashedPassword });
    const token = jwt.sign({ email: user.email, userid: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/profile');
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).render('register', { error: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await UserModel.findOne({ email }).lean();
    if (!user) return res.status(400).render('login', { error: 'User does not exist' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).render('login', { error: 'Invalid credentials' });

    const token = jwt.sign({ email: user.email, userid: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/profile');
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).render('login', { error: 'Server error' });
  }
});

app.get('/profile', ensureAuthenticated, async (req, res) => {
  try {
    const user = await UserModel.findById(req.user.userid).lean();
    const posts = await PostModel.find({ user: user._id }).sort({ createdAt: -1 }).lean();
    res.render('profile', { user, posts });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).render('error', { message: 'Server error' });
  }
});

app.post('/post', ensureAuthenticated, upload.single('image'), async (req, res) => {
  try {
    const user = await UserModel.findById(req.user.userid);
    if (!user) return res.status(404).render('error', { message: 'User not found' });

    const { title, content } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    const post = await PostModel.create({
      user: user._id,
      title,
      content,
      imageUrl,
      likes: [],
      createdAt: new Date(),
    });

    user.posts = user.posts || [];
    user.posts.push(post._id);
    await user.save();

    res.redirect('/profile');
  } catch (err) {
    console.error('Post creation error:', err);
    res.status(500).render('error', { message: 'Failed to create post' });
  }
});

app.get('/like/:id', ensureAuthenticated, async (req, res) => {
  try {
    const post = await PostModel.findById(req.params.id);
    if (!post) return res.status(404).render('error', { message: 'Post not found' });

    const userId = req.user.userid;
    const index = post.likes.indexOf(userId);
    if (index === -1) post.likes.push(userId);
    else post.likes.splice(index, 1);

    await post.save();
    res.redirect('/');
  } catch (err) {
    console.error('Like error:', err);
    res.status(500).render('error', { message: 'Failed to like post' });
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// Route to view all posts (optional)
app.get('/posts', async (req, res) => {
  try {
    const posts = await PostModel.find()
      .populate('user', 'username')
      .sort({ createdAt: -1 })
      .lean();

    res.render('viewPosts', { posts, user: null }); // user can be set if you want to check auth here
  } catch (err) {
    console.error('Fetch posts error:', err);
    res.status(500).render('error', { message: 'Server error while fetching posts' });
  }
});

app.listen(3000, () => {
  console.log('🚀 Server is running on http://localhost:3000');
});
