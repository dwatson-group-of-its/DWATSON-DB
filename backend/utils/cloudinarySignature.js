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
 * Cloudinary signature requirements:
 * 1. Sort all parameters alphabetically (excluding signature itself)
 * 2. Format as "key=value" pairs
 * 3. Join with "&"
 * 4. Append API_SECRET
 * 5. SHA-1 hash
 * 
 * @param {Object} options - Upload options (folder, resource_type, etc.)
 * @param {string} apiKey - Cloudinary API key
 * @param {string} apiSecret - Cloudinary API secret
 * @returns {Object} - Parameters with timestamp, api_key, and signature
 */
function prepareSignedUploadParams(options, apiKey, apiSecret) {
    // Generate timestamp (Unix timestamp in seconds)
    const timestamp = generateTimestamp();
    
    // Build parameters object for signing
    // Note: Only include parameters that should be signed
    // Exclude: signature, file, resource_type (handled separately by SDK)
    const paramsForSigning = {
        folder: options.folder || '',
        timestamp: timestamp,
        unique_filename: options.unique_filename ? '1' : undefined,
        use_filename: options.use_filename ? '1' : undefined
    };
    
    // Remove undefined values
    Object.keys(paramsForSigning).forEach(key => {
        if (paramsForSigning[key] === undefined || paramsForSigning[key] === null) {
            delete paramsForSigning[key];
        }
    });
    
    // Convert boolean values to strings for signing
    if (paramsForSigning.unique_filename !== undefined) {
        paramsForSigning.unique_filename = String(paramsForSigning.unique_filename);
    }
    if (paramsForSigning.use_filename !== undefined) {
        paramsForSigning.use_filename = String(paramsForSigning.use_filename);
    }
    
    // Generate signature from parameters
    const signature = generateCloudinarySignature(paramsForSigning, apiSecret);
    
    // Build final upload parameters
    // Include all original options plus signature-related params
    const uploadParams = {
        ...options,
        timestamp: timestamp,
        api_key: apiKey,
        signature: signature
    };
    
    // Remove undefined values from final params
    Object.keys(uploadParams).forEach(key => {
        if (uploadParams[key] === undefined || uploadParams[key] === null) {
            delete uploadParams[key];
        }
    });
    
    return uploadParams;
}

module.exports = {
    generateCloudinarySignature,
    generateTimestamp,
    prepareSignedUploadParams
};

