const { cloudinary, isConfigured } = require('../config/cloudinary');
const fs = require('fs');
const path = require('path');

// Helper function to check if Cloudinary is configured
const checkCloudinaryConfig = () => {
    if (!isConfigured || !cloudinary) {
        throw new Error(
            'Cloudinary is not configured. Please add CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET to your .env file. ' +
            'Get your credentials from https://cloudinary.com/console'
        );
    }
};

/**
 * Upload image to Cloudinary
 * @param {String} filePath - Path to the file to upload
 * @param {Object} options - Upload options (folder, transformation, etc.)
 * @returns {Promise<Object>} - Cloudinary upload result with secure URL
 */
const uploadToCloudinary = async (filePath, options = {}) => {
    try {
        // Check if Cloudinary is configured
        checkCloudinaryConfig();

        const defaultOptions = {
            folder: 'products', // Default folder in Cloudinary
            resource_type: 'auto', // Auto-detect image/video
            overwrite: false,
            invalidate: true, // Invalidate CDN cache
            ...options
        };

        // Upload to Cloudinary
        const result = await cloudinary.uploader.upload(filePath, defaultOptions);

        // Return the secure URL and public ID
        return {
            success: true,
            url: result.secure_url,
            publicId: result.public_id,
            width: result.width,
            height: result.height,
            format: result.format,
            bytes: result.bytes,
            assetId: result.asset_id
        };
    } catch (error) {
        console.error('Cloudinary upload error:', error);
        throw new Error(`Failed to upload image to Cloudinary: ${error.message}`);
    }
};

/**
 * Delete image from Cloudinary
 * @param {String} publicId - Cloudinary public ID of the image
 * @returns {Promise<Object>} - Deletion result
 */
const deleteFromCloudinary = async (publicId) => {
    try {
        // Check if Cloudinary is configured
        checkCloudinaryConfig();

        const result = await cloudinary.uploader.destroy(publicId);
        return {
            success: result.result === 'ok',
            result: result.result
        };
    } catch (error) {
        console.error('Cloudinary delete error:', error);
        throw new Error(`Failed to delete image from Cloudinary: ${error.message}`);
    }
};

/**
 * Upload image from buffer (for direct upload without saving to disk first)
 * @param {Buffer} buffer - File buffer
 * @param {String} filename - Original filename
 * @param {Object} options - Upload options
 * @returns {Promise<Object>} - Cloudinary upload result
 */
const uploadBufferToCloudinary = async (buffer, filename, options = {}) => {
    return new Promise((resolve, reject) => {
        try {
            // Check if Cloudinary is configured
            checkCloudinaryConfig();
        } catch (error) {
            reject(error);
            return;
        }

        const defaultOptions = {
            folder: 'products',
            resource_type: 'auto',
            ...options
        };

        const uploadStream = cloudinary.uploader.upload_stream(
            defaultOptions,
            (error, result) => {
                if (error) {
                    reject(new Error(`Failed to upload image to Cloudinary: ${error.message}`));
                } else {
                    resolve({
                        success: true,
                        url: result.secure_url,
                        publicId: result.public_id,
                        width: result.width,
                        height: result.height,
                        format: result.format,
                        bytes: result.bytes,
                        assetId: result.asset_id
                    });
                }
            }
        );

        uploadStream.end(buffer);
    });
};

module.exports = {
    uploadToCloudinary,
    deleteFromCloudinary,
    uploadBufferToCloudinary
};

