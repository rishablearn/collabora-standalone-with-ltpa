const ldap = require('ldapjs');
const logger = require('../utils/logger');

// Enable LDAP debug logging if DEBUG_LDAP is set
const DEBUG_LDAP = process.env.DEBUG_LDAP === 'true';

function ldapDebug(message, data = {}) {
  if (DEBUG_LDAP) {
    logger.info(`[LDAP DEBUG] ${message}`, data);
  }
}

/**
 * LDAP Authentication Service
 * Supports Active Directory, OpenLDAP, IBM Domino, and other LDAP servers
 */
class LDAPService {
  constructor() {
    // Helper to strip surrounding quotes from env values
    const stripQuotes = (val) => {
      if (!val) return val;
      // Remove surrounding single or double quotes that may have been included
      if ((val.startsWith("'") && val.endsWith("'")) || 
          (val.startsWith('"') && val.endsWith('"'))) {
        return val.slice(1, -1);
      }
      return val;
    };
    
    this.config = {
      url: stripQuotes(process.env.LDAP_URL) || 'ldap://localhost:389',
      baseDN: stripQuotes(process.env.LDAP_BASE_DN) || 'dc=example,dc=com',
      bindDN: stripQuotes(process.env.LDAP_BIND_DN) || '',
      bindPassword: stripQuotes(process.env.LDAP_BIND_PASSWORD) || '',
      userSearchBase: stripQuotes(process.env.LDAP_USER_SEARCH_BASE) || '',
      userSearchFilter: stripQuotes(process.env.LDAP_USER_SEARCH_FILTER) || '(uid={{username}})',
      groupSearchBase: process.env.LDAP_GROUP_SEARCH_BASE || 'ou=groups',
      groupSearchFilter: process.env.LDAP_GROUP_SEARCH_FILTER || '(member={{dn}})',
      usernameAttribute: process.env.LDAP_USERNAME_ATTR || 'uid',
      emailAttribute: process.env.LDAP_EMAIL_ATTR || 'mail',
      displayNameAttribute: process.env.LDAP_DISPLAY_NAME_ATTR || 'cn',
      adminGroup: process.env.LDAP_ADMIN_GROUP || 'cn=admins',
      // Domino-specific attributes
      dominoMode: process.env.LDAP_DOMINO_MODE === 'true',
      tlsOptions: {
        rejectUnauthorized: process.env.LDAP_TLS_REJECT_UNAUTHORIZED !== 'false'
      },
      timeout: parseInt(process.env.LDAP_TIMEOUT) || 10000,
      connectTimeout: parseInt(process.env.LDAP_CONNECT_TIMEOUT) || 15000,
      // Additional options for compatibility
      referrals: process.env.LDAP_FOLLOW_REFERRALS !== 'false',
      idleTimeout: parseInt(process.env.LDAP_IDLE_TIMEOUT) || 30000
    };
    
    ldapDebug('LDAP Service initialized with config', {
      url: this.config.url,
      baseDN: this.config.baseDN,
      bindDN: this.config.bindDN ? '(set)' : '(anonymous)',
      userSearchBase: this.config.userSearchBase,
      userSearchFilter: this.config.userSearchFilter,
      usernameAttribute: this.config.usernameAttribute,
      dominoMode: this.config.dominoMode
    });
  }

  /**
   * Create LDAP client connection
   */
  createClient() {
    const clientOptions = {
      url: this.config.url,
      timeout: this.config.timeout,
      connectTimeout: this.config.connectTimeout,
      idleTimeout: this.config.idleTimeout,
      reconnect: false,
      strictDN: false // Be lenient with DN parsing for Domino compatibility
    };

    if (this.config.url.startsWith('ldaps://')) {
      clientOptions.tlsOptions = this.config.tlsOptions;
    }

    ldapDebug('Creating LDAP client', { url: this.config.url });
    
    const client = ldap.createClient(clientOptions);
    
    // Add error handler to prevent unhandled errors
    client.on('error', (err) => {
      ldapDebug('LDAP client error', { error: err.message, code: err.code });
      logger.error('LDAP client error', { error: err.message, code: err.code });
    });
    
    client.on('connect', () => {
      ldapDebug('LDAP client connected');
    });
    
    client.on('timeout', () => {
      ldapDebug('LDAP client timeout');
    });
    
    return client;
  }

  /**
   * Bind to LDAP server with service account
   */
  async serviceBind(client) {
    return new Promise((resolve, reject) => {
      if (!this.config.bindDN) {
        ldapDebug('Using anonymous bind (no bindDN configured)');
        resolve();
        return;
      }

      ldapDebug('Attempting service bind', { bindDN: this.config.bindDN });
      
      client.bind(this.config.bindDN, this.config.bindPassword, (err) => {
        if (err) {
          ldapDebug('Service bind failed', { 
            error: err.message, 
            code: err.code,
            name: err.name,
            bindDN: this.config.bindDN
          });
          logger.error('LDAP service bind failed', { 
            error: err.message, 
            code: err.code,
            bindDN: this.config.bindDN 
          });
          reject(new Error(`LDAP service bind failed: ${err.message}`));
        } else {
          ldapDebug('Service bind successful');
          resolve();
        }
      });
    });
  }

  /**
   * Search for user in LDAP
   */
  async searchUser(client, username) {
    return new Promise((resolve, reject) => {
      // Build search base - handle case where userSearchBase might be empty
      let searchBase;
      if (this.config.userSearchBase) {
        searchBase = `${this.config.userSearchBase},${this.config.baseDN}`;
      } else {
        searchBase = this.config.baseDN;
      }
      
      // Escape special characters in username for LDAP filter
      const escapedUsername = this.escapeLDAPFilter(username);
      let filter = this.config.userSearchFilter.replace(/\{\{username\}\}/g, escapedUsername);
      
      // Validate filter has balanced parentheses
      const openParens = (filter.match(/\(/g) || []).length;
      const closeParens = (filter.match(/\)/g) || []).length;
      if (openParens !== closeParens) {
        ldapDebug('WARNING: Filter has unbalanced parentheses', { 
          filter, 
          openParens, 
          closeParens,
          originalFilter: this.config.userSearchFilter 
        });
      }
      
      ldapDebug('Filter constructed', { 
        originalFilter: this.config.userSearchFilter,
        escapedUsername,
        finalFilter: filter 
      });

      // Build attributes list - include common attributes for different LDAP servers
      const attributes = [
        this.config.usernameAttribute,
        this.config.emailAttribute,
        this.config.displayNameAttribute,
        'dn',
        'memberOf',
        // Domino LDAP attributes
        'dominoAccessGroups',
        'mailDomain',
        'shortName',
        // Active Directory attributes
        'sAMAccountName',
        'userPrincipalName',
        'displayName',
        // Common attributes
        'uid',
        'mail',
        'cn',
        'givenName',
        'sn'
      ];

      const opts = {
        filter,
        scope: 'sub',
        attributes,
        sizeLimit: 1,
        timeLimit: 10
      };

      ldapDebug('Searching for user', { searchBase, filter, attributes: opts.attributes });

      client.search(searchBase, opts, (err, res) => {
        if (err) {
          ldapDebug('Search initiation failed', { error: err.message, code: err.code });
          reject(err);
          return;
        }

        let user = null;
        let entriesFound = 0;

        res.on('searchEntry', (entry) => {
          entriesFound++;
          ldapDebug('Search entry found', { 
            dn: entry.objectName,
            attributeCount: entry.attributes.length,
            attributes: entry.attributes.map(a => ({ type: a.type, values: a.values }))
          });
          
          // Helper function to get attribute value (case-insensitive)
          const getAttr = (attrName) => {
            const attr = entry.attributes.find(a => 
              a.type.toLowerCase() === attrName.toLowerCase()
            );
            return attr?.values?.[0] || null;
          };
          
          // Helper function to get all values of an attribute
          const getAttrValues = (attrName) => {
            const attr = entry.attributes.find(a => 
              a.type.toLowerCase() === attrName.toLowerCase()
            );
            return attr?.values || [];
          };
          
          user = {
            dn: entry.objectName,
            // Try multiple username attributes
            username: getAttr(this.config.usernameAttribute) || 
                      getAttr('uid') || 
                      getAttr('sAMAccountName') ||
                      getAttr('shortName') ||
                      getAttr('cn'),
            // Try multiple email attributes
            email: getAttr(this.config.emailAttribute) || 
                   getAttr('mail') || 
                   getAttr('userPrincipalName'),
            // Try multiple display name attributes  
            displayName: getAttr(this.config.displayNameAttribute) || 
                         getAttr('displayName') || 
                         getAttr('cn') ||
                         getAttr('givenName'),
            // Group membership
            memberOf: getAttrValues('memberOf').concat(getAttrValues('dominoAccessGroups'))
          };
          
          ldapDebug('Parsed user entry', user);
        });

        res.on('searchReference', (referral) => {
          ldapDebug('Search referral received', { referral: referral.uris });
        });

        res.on('error', (err) => {
          ldapDebug('Search error', { error: err.message, code: err.code });
          reject(err);
        });

        res.on('end', (result) => {
          ldapDebug('Search completed', { 
            status: result?.status,
            entriesFound,
            userFound: !!user
          });
          resolve(user);
        });
      });
    });
  }
  
  /**
   * Escape special characters in LDAP filter values
   */
  escapeLDAPFilter(value) {
    if (!value) return '';
    return value
      .replace(/\\/g, '\\5c')
      .replace(/\*/g, '\\2a')
      .replace(/\(/g, '\\28')
      .replace(/\)/g, '\\29')
      .replace(/\x00/g, '\\00');
  }

  /**
   * Authenticate user with LDAP credentials
   */
  async authenticate(username, password) {
    ldapDebug('=== LDAP Authentication Started ===', { username });
    ldapDebug('Config', {
      url: this.config.url,
      baseDN: this.config.baseDN,
      userSearchBase: this.config.userSearchBase,
      userSearchFilter: this.config.userSearchFilter,
      dominoMode: this.config.dominoMode
    });
    
    const client = this.createClient();
    let connectionEstablished = false;

    try {
      // First, bind with service account to search for user
      ldapDebug('Step 1: Service bind');
      await this.serviceBind(client);
      connectionEstablished = true;
      
      // Search for user
      ldapDebug('Step 2: Search for user');
      const user = await this.searchUser(client, username);

      if (!user) {
        ldapDebug('User not found in LDAP', { username });
        logger.warn('LDAP user not found', { username });
        this.safeUnbind(client);
        return null;
      }

      ldapDebug('Step 3: User found, attempting user bind', { dn: user.dn });
      
      // Try to bind as the user to verify password
      return new Promise((resolve, reject) => {
        client.bind(user.dn, password, (err) => {
          this.safeUnbind(client);

          if (err) {
            ldapDebug('User bind failed (invalid password)', { 
              username, 
              error: err.message,
              code: err.code 
            });
            logger.warn('LDAP authentication failed', { username, error: err.message });
            resolve(null);
          } else {
            ldapDebug('User bind successful - authentication complete', { username });
            logger.info('LDAP authentication successful', { username });
            
            // Determine role based on group membership
            const isAdmin = user.memberOf.some(group => 
              group.toLowerCase().includes(this.config.adminGroup.toLowerCase())
            );

            const result = {
              username: user.username || username,
              email: user.email || `${username}@${this.config.baseDN.replace(/dc=/gi, '').replace(/,/g, '.')}`,
              displayName: user.displayName || username,
              role: isAdmin ? 'admin' : 'user',
              ldapDN: user.dn,
              groups: user.memberOf
            };
            
            ldapDebug('Returning user data', result);
            resolve(result);
          }
        });
      });
    } catch (error) {
      ldapDebug('LDAP authentication error', { 
        error: error.message, 
        stack: error.stack,
        connectionEstablished 
      });
      logger.error('LDAP authentication error', { error: error.message });
      this.safeUnbind(client);
      throw error;
    }
  }
  
  /**
   * Safely unbind client, ignoring errors
   */
  safeUnbind(client) {
    try {
      client.unbind();
    } catch (e) {
      ldapDebug('Unbind error (ignored)', { error: e.message });
    }
  }

  /**
   * Get user groups from LDAP
   */
  async getUserGroups(username) {
    const client = this.createClient();

    try {
      await this.serviceBind(client);
      const user = await this.searchUser(client, username);
      client.unbind();

      if (!user) {
        return [];
      }

      return user.memberOf || [];
    } catch (error) {
      logger.error('LDAP get groups error', { error: error.message });
      client.unbind();
      return [];
    }
  }

  /**
   * Check if user exists in LDAP (without password verification)
   * Used for LDAP+LTPA combined authentication
   */
  async userExistsInLDAP(username) {
    const client = this.createClient();

    try {
      await this.serviceBind(client);
      const user = await this.searchUser(client, username);
      client.unbind();
      
      if (user) {
        logger.info('User found in LDAP', { username });
        return true;
      }
      
      logger.warn('User not found in LDAP', { username });
      return false;
    } catch (error) {
      logger.error('LDAP user check error', { error: error.message });
      client.unbind();
      return false;
    }
  }

  /**
   * Get user details from LDAP without authentication
   * Used for syncing user info from LDAP
   */
  async getUserFromLDAP(username) {
    const client = this.createClient();

    try {
      await this.serviceBind(client);
      const user = await this.searchUser(client, username);
      client.unbind();
      
      if (user) {
        return {
          username: user.username || username,
          email: user.email,
          displayName: user.displayName,
          groups: user.memberOf,
          dn: user.dn
        };
      }
      
      return null;
    } catch (error) {
      logger.error('LDAP get user error', { error: error.message });
      client.unbind();
      return null;
    }
  }

  /**
   * Test LDAP connection
   */
  async testConnection() {
    const client = this.createClient();

    try {
      await this.serviceBind(client);
      client.unbind();
      return { success: true, message: 'LDAP connection successful' };
    } catch (error) {
      return { success: false, message: error.message };
    }
  }
}

module.exports = new LDAPService();
