const crypto = require('crypto');

/**
 * Generate Cloudinary signature for uploads
 * Cloudinary signature format:
 * 1. Sort all parameters alphabetically by key
 * 2. Format as "key=value" pairs
 * 3. Join with "&"
 * 4. Append API_SECRET
 * 5. Hash using SHA-1
 * 
 * @param {Object} params - Upload parameters
 * @param {string} apiSecret - Cloudinary API secret
 * @returns {string} - SHA-1 hash signature
 */
function generateCloudinarySignature(params, apiSecret) {
    // Sort parameters alphabetically by key
    const sortedKeys = Object.keys(params).sort();
    
    // Create string to sign: "key1=value1&key2=value2&..."
    const stringToSign = sortedKeys
        .map(key => `${key}=${params[key]}`)
        .join('&');
    
    // Append API secret
    const stringWithSecret = stringToSign + apiSecret;
    
    // Generate SHA-1 hash
    const signature = crypto
        .createHash('sha1')
        .update(stringWithSecret)
        .digest('hex');
    
    return signature;
}

/**
 * Generate timestamp for Cloudinary upload
 * @returns {number} - Unix timestamp in seconds
 */
function generateTimestamp() {
    return Math.floor(Date.now() / 1000);
}

/**
 * Prepare upload parameters with signature
 * @param {Object} options - Upload options (folder, resource_type, etc.)
 * @param {string} apiKey - Cloudinary API key
 * @param {string} apiSecret - Cloudinary API secret
 * @returns {Object} - Parameters with timestamp, api_key, and signature
 */
function prepareSignedUploadParams(options, apiKey, apiSecret) {
    // Generate timestamp
    const timestamp = generateTimestamp();
    
    // Build parameters object (exclude signature-related params)
    const params = {
        ...options,
        timestamp: timestamp,
        api_key: apiKey
    };
    
    // Remove any undefined values
    Object.keys(params).forEach(key => {
        if (params[key] === undefined || params[key] === null) {
            delete params[key];
        }
    });
    
    // Generate signature
    const signature = generateCloudinarySignature(params, apiSecret);
    
    // Add signature to params
    params.signature = signature;
    
    return params;
}

module.exports = {
    generateCloudinarySignature,
    generateTimestamp,
    prepareSignedUploadParams
};

