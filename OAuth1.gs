/**
 * OAuth1 Library for Google Apps Script
 * Source: https://github.com/googleworkspace/apps-script-oauth1
 * Bản đơn giản dùng để xác thực OAuth1 với Twitter và các dịch vụ khác.
 */

var OAuth1 = (function () {
  'use strict';

  /**
   * Create a new OAuth1 service.
   * @param {string} name
   * @return {OAuth1Service}
   */
  function createService(name) {
    return new OAuth1Service(name);
  }

  /**
   * OAuth1Service class.
   * @constructor
   */
  function OAuth1Service(name) {
    this.name_ = name;
    this.consumerKey_ = null;
    this.consumerSecret_ = null;
    this.accessTokenUrl_ = null;
    this.requestTokenUrl_ = null;
    this.authorizationUrl_ = null;
    this.callbackFunction_ = null;
    this.propertyStore_ = PropertiesService.getUserProperties();
    this.accessToken_ = null;
    this.accessTokenSecret_ = null;
  }

  OAuth1Service.prototype = {
    setConsumerKey: function (key) {
      this.consumerKey_ = key;
      return this;
    },

    setConsumerSecret: function (secret) {
      this.consumerSecret_ = secret;
      return this;
    },

    setAccessTokenUrl: function (url) {
      this.accessTokenUrl_ = url;
      return this;
    },

    setRequestTokenUrl: function (url) {
      this.requestTokenUrl_ = url;
      return this;
    },

    setAuthorizationUrl: function (url) {
      this.authorizationUrl_ = url;
      return this;
    },

    setCallbackFunction: function (callbackFunction) {
      this.callbackFunction_ = callbackFunction;
      return this;
    },

    setPropertyStore: function (propertyStore) {
      this.propertyStore_ = propertyStore;
      return this;
    },

    setAccessToken: function (token, secret) {
      this.accessToken_ = token;
      this.accessTokenSecret_ = secret;
      return this;
    },

    hasAccess: function () {
      return this.accessToken_ != null && this.accessTokenSecret_ != null;
    },

    /**
     * Fetch URL with OAuth1 authentication.
     * @param {string} url
     * @param {object} options
     * @return {HTTPResponse}
     */
    fetch: function (url, options) {
      if (!options) {
        options = {};
      }

      var method = options.method || 'get';
      method = method.toLowerCase();

      var oauthParams = this.getOAuthParameters(method, url, options);

      var authHeader = this.getAuthorizationHeader(oauthParams);

      if (!options.headers) {
        options.headers = {};
      }
      options.headers.Authorization = authHeader;

      // Remove payload if method GET
      if (method === 'get') {
        delete options.payload;
      }

      return UrlFetchApp.fetch(url, options);
    },

    getOAuthParameters: function (method, url, options) {
      var oauthParams = {
        oauth_consumer_key: this.consumerKey_,
        oauth_nonce: this.generateNonce_(),
        oauth_signature_method: 'HMAC-SHA1',
        oauth_timestamp: this.getTimestamp_(),
        oauth_version: '1.0'
      };

      if (this.accessToken_) {
        oauthParams.oauth_token = this.accessToken_;
      }

      var signature = this.getSignature_(method, url, oauthParams, options);
      oauthParams.oauth_signature = signature;

      return oauthParams;
    },

    getAuthorizationHeader: function (oauthParams) {
      var header = 'OAuth ';
      var params = [];

      for (var key in oauthParams) {
        if (oauthParams.hasOwnProperty(key)) {
          params.push(key + '="' + encodeURIComponent(oauthParams[key]) + '"');
        }
      }

      header += params.join(', ');

      return header;
    },

    getSignature_: function (method, url, oauthParams, options) {
      var params = this.collectParameters_(url, oauthParams, options);

      var baseString = this.constructBaseString_(method, url, params);

      var signingKey = encodeURIComponent(this.consumerSecret_) + '&';
      if (this.accessTokenSecret_) {
        signingKey += encodeURIComponent(this.accessTokenSecret_);
      }

      var signature = Utilities.computeHmacSha1Signature(baseString, signingKey);

      return signature.map(function (b) {
        return ('0' + (b & 0xff).toString(16)).slice(-2);
      }).join('');
    },

    collectParameters_: function (url, oauthParams, options) {
      var params = [];

      // Query params in url
      var queryParams = this.getQueryParameters_(url);
      for (var key in queryParams) {
        params.push([key, queryParams[key]]);
      }

      // OAuth params
      for (var key in oauthParams) {
        params.push([key, oauthParams[key]]);
      }

      // Payload params (for POST with form data)
      if (options.payload && typeof options.payload === 'object' && options.headers && options.headers['Content-Type'] === 'application/x-www-form-urlencoded') {
        for (var key in options.payload) {
          params.push([key, options.payload[key]]);
        }
      }

      // Sort parameters by name and value
      params.sort(function (a, b) {
        if (a[0] === b[0]) {
          return a[1] < b[1] ? -1 : 1;
        }
        return a[0] < b[0] ? -1 : 1;
      });

      return params;
    },

    constructBaseString_: function (method, url, params) {
      var baseUrl = url.split('?')[0];
      var paramString = params.map(function (p) {
        return encodeURIComponent(p[0]) + '=' + encodeURIComponent(p[1]);
      }).join('&');

      return [
        method.toUpperCase(),
        encodeURIComponent(baseUrl),
        encodeURIComponent(paramString)
      ].join('&');
    },

    getQueryParameters_: function (url) {
      var query = url.indexOf('?') >= 0 ? url.split('?')[1] : '';
      var result = {};
      if (!query) {
        return result;
      }
      var pairs = query.split('&');
      pairs.forEach(function (pair) {
        var parts = pair.split('=');
        if (parts.length === 2) {
          result[decodeURIComponent(parts[0])] = decodeURIComponent(parts[1]);
        }
      });
      return result;
    },

    generateNonce_: function () {
      var text = '';
      var possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      for (var i = 0; i < 32; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
      }
      return text;
    },

    getTimestamp_: function () {
      return Math.floor(new Date().getTime() / 1000);
    }
  };

  return {
    createService: createService
  };
})();
