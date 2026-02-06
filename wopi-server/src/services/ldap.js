const ldap = require('ldapjs');
const logger = require('../utils/logger');

/**
 * LDAP Authentication Service
 * Supports Active Directory and OpenLDAP
 */
class LDAPService {
  constructor() {
    this.config = {
      url: process.env.LDAP_URL || 'ldap://localhost:389',
      baseDN: process.env.LDAP_BASE_DN || 'dc=example,dc=com',
      bindDN: process.env.LDAP_BIND_DN || '',
      bindPassword: process.env.LDAP_BIND_PASSWORD || '',
      userSearchBase: process.env.LDAP_USER_SEARCH_BASE || 'ou=users',
      userSearchFilter: process.env.LDAP_USER_SEARCH_FILTER || '(uid={{username}})',
      groupSearchBase: process.env.LDAP_GROUP_SEARCH_BASE || 'ou=groups',
      groupSearchFilter: process.env.LDAP_GROUP_SEARCH_FILTER || '(member={{dn}})',
      usernameAttribute: process.env.LDAP_USERNAME_ATTR || 'uid',
      emailAttribute: process.env.LDAP_EMAIL_ATTR || 'mail',
      displayNameAttribute: process.env.LDAP_DISPLAY_NAME_ATTR || 'cn',
      adminGroup: process.env.LDAP_ADMIN_GROUP || 'cn=admins',
      tlsOptions: {
        rejectUnauthorized: process.env.LDAP_TLS_REJECT_UNAUTHORIZED !== 'false'
      },
      timeout: parseInt(process.env.LDAP_TIMEOUT) || 5000,
      connectTimeout: parseInt(process.env.LDAP_CONNECT_TIMEOUT) || 10000
    };
  }

  /**
   * Create LDAP client connection
   */
  createClient() {
    const clientOptions = {
      url: this.config.url,
      timeout: this.config.timeout,
      connectTimeout: this.config.connectTimeout
    };

    if (this.config.url.startsWith('ldaps://')) {
      clientOptions.tlsOptions = this.config.tlsOptions;
    }

    return ldap.createClient(clientOptions);
  }

  /**
   * Bind to LDAP server with service account
   */
  async serviceBind(client) {
    return new Promise((resolve, reject) => {
      if (!this.config.bindDN) {
        // Anonymous bind
        resolve();
        return;
      }

      client.bind(this.config.bindDN, this.config.bindPassword, (err) => {
        if (err) {
          logger.error('LDAP service bind failed', { error: err.message });
          reject(new Error('LDAP service bind failed'));
        } else {
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
      const searchBase = `${this.config.userSearchBase},${this.config.baseDN}`;
      const filter = this.config.userSearchFilter.replace('{{username}}', username);

      const opts = {
        filter,
        scope: 'sub',
        attributes: [
          this.config.usernameAttribute,
          this.config.emailAttribute,
          this.config.displayNameAttribute,
          'dn',
          'memberOf'
        ]
      };

      client.search(searchBase, opts, (err, res) => {
        if (err) {
          reject(err);
          return;
        }

        let user = null;

        res.on('searchEntry', (entry) => {
          user = {
            dn: entry.objectName,
            username: entry.attributes.find(a => a.type === this.config.usernameAttribute)?.values[0],
            email: entry.attributes.find(a => a.type === this.config.emailAttribute)?.values[0],
            displayName: entry.attributes.find(a => a.type === this.config.displayNameAttribute)?.values[0],
            memberOf: entry.attributes.find(a => a.type === 'memberOf')?.values || []
          };
        });

        res.on('error', (err) => {
          reject(err);
        });

        res.on('end', () => {
          resolve(user);
        });
      });
    });
  }

  /**
   * Authenticate user with LDAP credentials
   */
  async authenticate(username, password) {
    const client = this.createClient();

    try {
      // First, bind with service account to search for user
      await this.serviceBind(client);

      // Search for user
      const user = await this.searchUser(client, username);

      if (!user) {
        logger.warn('LDAP user not found', { username });
        return null;
      }

      // Try to bind as the user to verify password
      return new Promise((resolve, reject) => {
        client.bind(user.dn, password, (err) => {
          client.unbind();

          if (err) {
            logger.warn('LDAP authentication failed', { username, error: err.message });
            resolve(null);
          } else {
            logger.info('LDAP authentication successful', { username });
            
            // Determine role based on group membership
            const isAdmin = user.memberOf.some(group => 
              group.toLowerCase().includes(this.config.adminGroup.toLowerCase())
            );

            resolve({
              username: user.username || username,
              email: user.email || `${username}@${this.config.baseDN.replace(/dc=/g, '').replace(/,/g, '.')}`,
              displayName: user.displayName || username,
              role: isAdmin ? 'admin' : 'user',
              ldapDN: user.dn,
              groups: user.memberOf
            });
          }
        });
      });
    } catch (error) {
      logger.error('LDAP authentication error', { error: error.message });
      client.unbind();
      throw error;
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
