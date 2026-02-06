const crypto = require('crypto');
const logger = require('../utils/logger');

/**
 * LTPA2 Token Service
 * Handles IBM WebSphere/Liberty LTPA2 token validation and generation
 * 
 * LTPA2 Token Format:
 * - Base64 encoded
 * - Contains: expire time, user info, signature
 * - Encrypted with 3DES using shared secret key
 */
class LTPAService {
  constructor() {
    this.config = {
      // LTPA shared secret key (base64 encoded)
      secretKey: process.env.LTPA_SECRET_KEY || '',
      // LTPA public key for signature verification (base64 encoded)  
      publicKey: process.env.LTPA_PUBLIC_KEY || '',
      // LTPA private key for token generation (base64 encoded)
      privateKey: process.env.LTPA_PRIVATE_KEY || '',
      // Token cookie name
      cookieName: process.env.LTPA_COOKIE_NAME || 'LtpaToken2',
      // Token realm
      realm: process.env.LTPA_REALM || 'defaultRealm',
      // Token expiration in seconds (default 2 hours)
      tokenExpiration: parseInt(process.env.LTPA_TOKEN_EXPIRATION) || 7200,
      // Trusted domains for SSO
      trustedDomains: (process.env.LTPA_TRUSTED_DOMAINS || '').split(',').filter(Boolean)
    };

    // Derived keys for LTPA2
    this.keys = this.deriveKeys();
  }

  /**
   * Derive encryption and signature keys from LTPA secret
   */
  deriveKeys() {
    if (!this.config.secretKey) {
      logger.warn('LTPA secret key not configured');
      return null;
    }

    try {
      const secretKeyBuffer = Buffer.from(this.config.secretKey, 'base64');
      
      // LTPA2 uses SHA-1 to derive keys
      const sha1 = crypto.createHash('sha1');
      sha1.update(secretKeyBuffer);
      const derivedKey = sha1.digest();

      return {
        // 3DES key (24 bytes)
        desKey: Buffer.concat([derivedKey, derivedKey.slice(0, 4)]),
        // HMAC key
        hmacKey: derivedKey
      };
    } catch (error) {
      logger.error('Failed to derive LTPA keys', { error: error.message });
      return null;
    }
  }

  /**
   * Decrypt LTPA2 token
   */
  decryptToken(encryptedToken) {
    if (!this.keys) {
      throw new Error('LTPA keys not configured');
    }

    try {
      const tokenBuffer = Buffer.from(encryptedToken, 'base64');
      
      // LTPA2 uses 3DES-CBC with IV as first 8 bytes
      const iv = tokenBuffer.slice(0, 8);
      const encrypted = tokenBuffer.slice(8);

      const decipher = crypto.createDecipheriv('des-ede3-cbc', this.keys.desKey, iv);
      decipher.setAutoPadding(true);

      let decrypted = decipher.update(encrypted);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      return decrypted.toString('utf8');
    } catch (error) {
      logger.error('LTPA token decryption failed', { error: error.message });
      throw new Error('Invalid LTPA token');
    }
  }

  /**
   * Encrypt data for LTPA2 token
   */
  encryptToken(data) {
    if (!this.keys) {
      throw new Error('LTPA keys not configured');
    }

    try {
      // Generate random IV
      const iv = crypto.randomBytes(8);
      
      const cipher = crypto.createCipheriv('des-ede3-cbc', this.keys.desKey, iv);
      cipher.setAutoPadding(true);

      let encrypted = cipher.update(data, 'utf8');
      encrypted = Buffer.concat([encrypted, cipher.final()]);

      // Prepend IV to encrypted data
      const token = Buffer.concat([iv, encrypted]);
      
      return token.toString('base64');
    } catch (error) {
      logger.error('LTPA token encryption failed', { error: error.message });
      throw new Error('Failed to generate LTPA token');
    }
  }

  /**
   * Parse LTPA2 token content
   * Format: u:user:<realm>/<username>$<attributes>%<expireTime>%<signature>
   */
  parseTokenContent(content) {
    try {
      // Remove null padding
      content = content.replace(/\0+$/, '');

      // Split by % to get parts
      const parts = content.split('%');
      if (parts.length < 2) {
        throw new Error('Invalid token format');
      }

      const userPart = parts[0];
      const expireTime = parseInt(parts[1], 10);

      // Parse user info (format: u:user:realm/username or uid=username,...)
      let username = '';
      let realm = '';

      if (userPart.startsWith('u:user:')) {
        const userInfo = userPart.substring(7);
        const slashIndex = userInfo.indexOf('/');
        if (slashIndex !== -1) {
          realm = userInfo.substring(0, slashIndex);
          username = userInfo.substring(slashIndex + 1).split('$')[0];
        } else {
          username = userInfo.split('$')[0];
        }
      } else if (userPart.includes('uid=')) {
        // LDAP DN format
        const match = userPart.match(/uid=([^,]+)/i);
        if (match) {
          username = match[1];
        }
      }

      // Extract attributes if present
      const attributes = {};
      const attrMatch = userPart.match(/\$(.+)$/);
      if (attrMatch) {
        const attrPairs = attrMatch[1].split('$');
        for (const pair of attrPairs) {
          const [key, value] = pair.split(':');
          if (key && value) {
            attributes[key] = value;
          }
        }
      }

      return {
        username,
        realm,
        expireTime,
        attributes,
        isExpired: Date.now() > expireTime
      };
    } catch (error) {
      logger.error('LTPA token parsing failed', { error: error.message });
      throw new Error('Invalid LTPA token content');
    }
  }

  /**
   * Validate LTPA2 token from cookie
   */
  async validateToken(token) {
    if (!token) {
      return null;
    }

    try {
      // URL decode if needed
      const decodedToken = decodeURIComponent(token);
      
      // Decrypt token
      const content = this.decryptToken(decodedToken);
      
      // Parse token content
      const tokenData = this.parseTokenContent(content);

      if (tokenData.isExpired) {
        logger.warn('LTPA token expired', { username: tokenData.username });
        return null;
      }

      logger.info('LTPA token validated', { username: tokenData.username });

      return {
        username: tokenData.username,
        realm: tokenData.realm,
        attributes: tokenData.attributes,
        expireTime: tokenData.expireTime
      };
    } catch (error) {
      logger.error('LTPA token validation failed', { error: error.message });
      return null;
    }
  }

  /**
   * Generate LTPA2 token for user
   */
  generateToken(username, attributes = {}) {
    if (!this.keys) {
      throw new Error('LTPA keys not configured');
    }

    const expireTime = Date.now() + (this.config.tokenExpiration * 1000);
    
    // Build token content
    let content = `u:user:${this.config.realm}/${username}`;
    
    // Add attributes
    if (Object.keys(attributes).length > 0) {
      const attrString = Object.entries(attributes)
        .map(([k, v]) => `${k}:${v}`)
        .join('$');
      content += `$${attrString}`;
    }
    
    content += `%${expireTime}`;
    
    // Add HMAC signature
    const hmac = crypto.createHmac('sha1', this.keys.hmacKey);
    hmac.update(content);
    const signature = hmac.digest('base64');
    content += `%${signature}`;

    // Encrypt and return
    return this.encryptToken(content);
  }

  /**
   * Get token from request (cookie or header)
   */
  getTokenFromRequest(req) {
    // Try cookie first
    const cookieToken = req.cookies?.[this.config.cookieName];
    if (cookieToken) {
      return cookieToken;
    }

    // Try Authorization header
    const authHeader = req.headers['authorization'];
    if (authHeader?.startsWith('LTPA ')) {
      return authHeader.substring(5);
    }

    // Try custom header
    const ltpaHeader = req.headers['x-ltpa-token'];
    if (ltpaHeader) {
      return ltpaHeader;
    }

    return null;
  }

  /**
   * Set LTPA token cookie
   */
  setTokenCookie(res, token, domain = null) {
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: this.config.tokenExpiration * 1000,
      path: '/'
    };

    if (domain) {
      cookieOptions.domain = domain;
    }

    res.cookie(this.config.cookieName, token, cookieOptions);
  }

  /**
   * Clear LTPA token cookie
   */
  clearTokenCookie(res, domain = null) {
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      path: '/'
    };

    if (domain) {
      cookieOptions.domain = domain;
    }

    res.clearCookie(this.config.cookieName, cookieOptions);
  }

  /**
   * Test LTPA configuration
   */
  testConfiguration() {
    if (!this.config.secretKey) {
      return { success: false, message: 'LTPA secret key not configured' };
    }

    if (!this.keys) {
      return { success: false, message: 'Failed to derive LTPA keys' };
    }

    // Test token generation and validation
    try {
      const testToken = this.generateToken('testuser', { test: 'value' });
      const content = this.decryptToken(testToken);
      const parsed = this.parseTokenContent(content);

      if (parsed.username !== 'testuser') {
        return { success: false, message: 'Token round-trip validation failed' };
      }

      return { success: true, message: 'LTPA configuration valid' };
    } catch (error) {
      return { success: false, message: error.message };
    }
  }
}

module.exports = new LTPAService();
