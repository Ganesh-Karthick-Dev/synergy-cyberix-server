# Cyberix Server

A modern, scalable backend server built with Node.js, Express.js, TypeScript, and Prisma ORM.

## 🚀 Features

- **TypeScript**: Full type safety and modern JavaScript features
- **Express.js**: Fast, unopinionated web framework
- **Prisma ORM**: Type-safe database access with auto-generated client
- **JWT Authentication**: Secure authentication with refresh tokens
- **Passport.js**: Flexible authentication middleware
- **Input Validation**: Request validation with express-validator
- **Rate Limiting**: Built-in rate limiting for API protection
- **CORS**: Cross-origin resource sharing configuration
- **Security**: Helmet.js for security headers
- **Logging**: Structured logging with Morgan
- **Error Handling**: Comprehensive error handling middleware
- **Modular Architecture**: Clean separation of concerns

## 📁 Project Structure

```
src/
├── config/           # Configuration files
│   ├── db.ts         # Database configuration
│   ├── env.config.ts # Environment variables
│   └── passport.ts   # Passport.js configuration
├── decorators/       # Custom decorators
│   ├── authenticate.decorator.ts
│   ├── controller.decorator.ts
│   ├── file-upload.decorator.ts
│   ├── method.decorator.ts
│   └── middleware.decorator.ts
├── middlewares/      # Custom middleware
│   ├── auth.middleware.ts
│   ├── error.middleware.ts
│   ├── not-found.middleware.ts
│   └── validation.middleware.ts
├── modules/          # Feature modules
│   ├── controllers/ # Route controllers
│   ├── dtos/        # Data Transfer Objects
│   ├── services/    # Business logic
│   └── model/       # Database models
├── routes/          # API routes
│   ├── auth.routes.ts
│   ├── user.routes.ts
│   ├── post.routes.ts
│   └── api.routes.ts
├── utils/           # Utility functions
│   ├── logger.ts
│   └── response.ts
├── types/           # TypeScript type definitions
└── index.ts         # Application entry point
```

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cyberix-server
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp env.example .env
   ```
   
   Update the `.env` file with your configuration:
   ```env
   DATABASE_URL="postgresql://username:password@localhost:5432/cyberix_db?schema=public"
   JWT_SECRET="your-super-secret-jwt-key-here"
   JWT_REFRESH_SECRET="your-super-secret-refresh-key-here"
   SESSION_SECRET="your-super-secret-session-key-here"
   ```

4. **Set up the database**
   ```bash
   # Generate Prisma client
   npm run db:generate
   
   # Run database migrations
   npm run db:migrate
   
   # Seed the database
   npm run db:seed
   ```

5. **Start the development server**
   ```bash
   npm run dev
   ```

## 📚 API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/refresh-token` - Refresh access token
- `POST /api/auth/logout` - Logout user
- `GET /api/auth/profile` - Get user profile

### Users
- `GET /api/users/profile` - Get current user profile
- `PUT /api/users/profile` - Update user profile
- `PUT /api/users/change-password` - Change password
- `DELETE /api/users/account` - Delete user account
- `GET /api/users` - Get all users (Admin only)
- `GET /api/users/:id` - Get user by ID (Admin only)

### Posts
- `GET /api/posts` - Get all posts
- `GET /api/posts/published` - Get published posts
- `GET /api/posts/:id` - Get post by ID
- `GET /api/posts/slug/:slug` - Get post by slug
- `POST /api/posts` - Create new post (Auth required)
- `PUT /api/posts/:id` - Update post (Auth required)
- `DELETE /api/posts/:id` - Delete post (Auth required)
- `GET /api/posts/user/posts` - Get user's posts (Auth required)

### Health Check
- `GET /health` - Server health status

## 🔧 Available Scripts

- `npm run dev` - Start development server with hot reload
- `npm run build` - Build the project
- `npm start` - Start production server
- `npm run db:generate` - Generate Prisma client
- `npm run db:push` - Push schema changes to database
- `npm run db:migrate` - Run database migrations
- `npm run db:seed` - Seed the database
- `npm run db:studio` - Open Prisma Studio
- `npm run lint` - Run ESLint
- `npm run lint:fix` - Fix ESLint errors

## 🗄️ Database Schema

The application uses the following main entities:

- **Users**: User accounts with authentication
- **Posts**: Blog posts with content and metadata
- **Comments**: Comments on posts
- **Tags**: Categorization tags for posts
- **Sessions**: User sessions for authentication

## 🔐 Authentication

The server uses JWT (JSON Web Tokens) for authentication:

- **Access Token**: Short-lived token for API access
- **Refresh Token**: Long-lived token for refreshing access tokens
- **Passport.js**: JWT and Local strategies for authentication

## 🛡️ Security Features

- **Rate Limiting**: Prevents API abuse
- **CORS**: Configurable cross-origin requests
- **Helmet**: Security headers
- **Input Validation**: Request validation and sanitization
- **Password Hashing**: bcrypt for secure password storage
- **JWT Security**: Secure token generation and validation

## 📝 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3000 |
| `NODE_ENV` | Environment | development |
| `DATABASE_URL` | Database connection string | - |
| `JWT_SECRET` | JWT signing secret | - |
| `JWT_REFRESH_SECRET` | Refresh token secret | - |
| `SESSION_SECRET` | Session secret | - |
| `CORS_ORIGIN` | CORS allowed origins | http://localhost:3000 |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For support and questions, please open an issue in the repository.
