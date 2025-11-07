import passport from 'passport';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { config } from './env.config';
import { prisma } from './db';
import bcrypt from 'bcryptjs';

// JWT Strategy
passport.use(new JwtStrategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: config.jwt.secret,
  algorithms: ['HS256']
}, async (payload, done) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: payload.userId },
      select: {
        id: true,
        email: true,
        username: true,
        role: true,
        status: true,
        createdAt: true,
        updatedAt: true
      }
    });

    if (user && user.status === 'ACTIVE') {
      // Transform user to include isActive for compatibility
      return done(null, { ...user, isActive: user.status === 'ACTIVE' });
    }
    
    return done(null, false);
  } catch (error) {
    return done(error, false);
  }
}));

// Local Strategy for login
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() }
    });

    if (!user || user.status !== 'ACTIVE') {
      return done(null, false, { message: 'Invalid credentials' });
    }

    // Check if user has a password (Google OAuth users may not have one)
    if (!user.password) {
      return done(null, false, { message: 'This account uses Google login. Please use Google sign-in.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return done(null, false, { message: 'Invalid credentials' });
    }

    // Transform user to include isActive for compatibility
    return done(null, { ...user, isActive: user.status === 'ACTIVE' });
  } catch (error) {
    return done(error, false);
  }
}));

// Google OAuth Strategy - Register with name 'google'
if (config.google) {
  console.log('📝 Registering Google OAuth strategy...');
  console.log('📝 [Passport] Callback URL:', config.google.callbackURL);
  passport.use('google', new GoogleStrategy({
    clientID: config.google.clientId,
    clientSecret: config.google.clientSecret,
    callbackURL: config.google.callbackURL
  }, async (accessToken, refreshToken, profile, done) => {
    console.log('🟣 [Passport Strategy] Google OAuth callback received');
    console.log('🟣 [Passport Strategy] Profile:', {
      id: profile.id,
      displayName: profile.displayName,
      emails: profile.emails?.map(e => e.value),
      photos: profile.photos?.map(p => p.value),
    });
    try {
      const { id, displayName, emails, photos } = profile;
      const email = emails?.[0]?.value?.toLowerCase();
      
      console.log('🟣 [Passport Strategy] Processing profile:', {
        googleId: id,
        email,
        displayName,
      });

      if (!email) {
        console.error('🟣 [Passport Strategy] No email found in Google profile');
        return done(new Error('No email found in Google profile'), false);
      }

      // Check if user exists by email or googleId
      console.log('🟣 [Passport Strategy] Checking for existing user...');
      let user = await prisma.user.findFirst({
        where: {
          OR: [
            { email },
            { googleId: id }
          ]
        }
      });
      console.log('🟣 [Passport Strategy] User found:', user ? {
        id: user.id,
        email: user.email,
        googleId: user.googleId,
      } : 'None - will create new user');

      if (user) {
        console.log('🟣 [Passport Strategy] Updating existing user...');
        // Update existing user with Google ID if not already set
        if (!user.googleId) {
          console.log('🟣 [Passport Strategy] Linking Google ID to existing user');
          user = await prisma.user.update({
            where: { id: user.id },
            data: { 
              googleId: id,
              emailVerified: true,
              avatar: photos?.[0]?.value || user.avatar,
              firstName: displayName?.split(' ')[0] || user.firstName,
              lastName: displayName?.split(' ').slice(1).join(' ') || user.lastName
            }
          });
        } else {
          console.log('🟣 [Passport Strategy] Updating user profile info');
          // Update avatar and name if available
          user = await prisma.user.update({
            where: { id: user.id },
            data: {
              avatar: photos?.[0]?.value || user.avatar,
              firstName: displayName?.split(' ')[0] || user.firstName,
              lastName: displayName?.split(' ').slice(1).join(' ') || user.lastName,
              emailVerified: true
            }
          });
        }
        console.log('🟣 [Passport Strategy] User updated successfully');
      } else {
        // Create new user
        console.log('🟣 [Passport Strategy] Creating new user...');
        const [firstName, ...lastNameParts] = displayName?.split(' ') || [];
        user = await prisma.user.create({
          data: {
            email,
            googleId: id,
            firstName,
            lastName: lastNameParts.join(' ') || null,
            avatar: photos?.[0]?.value || null,
            emailVerified: true,
            status: 'ACTIVE',
            role: 'USER'
          }
        });
        console.log('🟣 [Passport Strategy] New user created:', user.id);
      }

      console.log('🟣 [Passport Strategy] Final user status:', {
        id: user.id,
        email: user.email,
        status: user.status,
      });

      if (!user || user.status !== 'ACTIVE') {
        console.error('🟣 [Passport Strategy] Account is not active');
        return done(new Error('Account is not active'), false);
      }

      // Return user in the format expected by the system
      const userPayload = {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        status: user.status,
        isActive: user.status === 'ACTIVE',
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      };

      console.log('🟣 [Passport Strategy] Returning user payload to callback');
      return done(null, userPayload as any);
    } catch (error: any) {
      console.error('🟣 [Passport Strategy] Error:', {
        message: error?.message,
        stack: error?.stack,
        name: error?.name,
      });
      return done(error, false);
    }
  }));
  console.log('✅ Google OAuth strategy registered successfully');
  
  // Google OAuth Strategy for Website - Register with name 'google-website'
  // IMPORTANT: Use the SAME callback URL as admin (already configured in Google Console)
  // We'll differentiate between admin and website in the callback handler
  console.log('📝 Registering Google OAuth strategy for website...');
  // Use the same callback URL as admin to avoid redirect_uri_mismatch
  const websiteCallbackUrl = config.google.callbackURL;
  
  console.log('📝 [Passport Website] Callback URL (reusing admin callback):', websiteCallbackUrl);
  passport.use('google-website', new GoogleStrategy({
    clientID: config.google.clientId,
    clientSecret: config.google.clientSecret,
    callbackURL: websiteCallbackUrl
  }, async (accessToken, refreshToken, profile, done) => {
    console.log('🟣 [Passport Website Strategy] Google OAuth callback received');
    console.log('🟣 [Passport Website Strategy] Profile:', {
      id: profile.id,
      displayName: profile.displayName,
      emails: profile.emails?.map(e => e.value),
      photos: profile.photos?.map(p => p.value),
    });
    try {
      const { id, displayName, emails, photos } = profile;
      const email = emails?.[0]?.value?.toLowerCase();
      
      if (!email) {
        console.error('🟣 [Passport Website Strategy] No email found in Google profile');
        return done(new Error('No email found in Google profile'), false);
      }

      // Check if user exists by email or googleId
      let user = await prisma.user.findFirst({
        where: {
          OR: [
            { email },
            { googleId: id }
          ]
        }
      });

      if (user) {
        // Update existing user with Google ID if not already set
        if (!user.googleId) {
          user = await prisma.user.update({
            where: { id: user.id },
            data: { 
              googleId: id,
              emailVerified: true,
              avatar: photos?.[0]?.value || user.avatar,
              firstName: displayName?.split(' ')[0] || user.firstName,
              lastName: displayName?.split(' ').slice(1).join(' ') || user.lastName
            }
          });
        } else {
          user = await prisma.user.update({
            where: { id: user.id },
            data: {
              avatar: photos?.[0]?.value || user.avatar,
              firstName: displayName?.split(' ')[0] || user.firstName,
              lastName: displayName?.split(' ').slice(1).join(' ') || user.lastName,
              emailVerified: true
            }
          });
        }
      } else {
        // Create new user
        const [firstName, ...lastNameParts] = displayName?.split(' ') || [];
        user = await prisma.user.create({
          data: {
            email,
            googleId: id,
            firstName,
            lastName: lastNameParts.join(' ') || null,
            avatar: photos?.[0]?.value || null,
            emailVerified: true,
            status: 'ACTIVE',
            role: 'USER'
          }
        });
      }

      if (!user || user.status !== 'ACTIVE') {
        console.error('🟣 [Passport Website Strategy] Account is not active');
        return done(new Error('Account is not active'), false);
      }

      // Return user in the format expected by the system
      const userPayload = {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        status: user.status,
        isActive: user.status === 'ACTIVE',
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      };

      return done(null, userPayload as any);
    } catch (error: any) {
      console.error('🟣 [Passport Website Strategy] Error:', error);
      return done(error, false);
    }
  }));
  console.log('✅ Google OAuth website strategy registered successfully');
} else {
  console.warn('⚠️  Google OAuth not configured - strategy will not be available');
}

// Serialize user for session
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        username: true,
        role: true,
        status: true,
        createdAt: true,
        updatedAt: true
      }
    });

    if (user && user.status === 'ACTIVE') {
      // Transform user to include isActive for compatibility
      return done(null, { ...user, isActive: user.status === 'ACTIVE' });
    }
    
    return done(null, false);
  } catch (error) {
    return done(error, false);
  }
});

export default passport;
