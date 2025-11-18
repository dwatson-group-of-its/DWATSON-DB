const express = require('express');
const router = express.Router();
const Banner = require('../models/Banner');
const Media = require('../models/Media');
const auth = require('../middleware/auth');
const adminAuth = require('../middleware/adminAuth');
const { uploadBanner, deleteTempFile } = require('../middleware/bannerUpload');
const { cloudinary, isConfigured } = require('../config/cloudinary');
const { prepareSignedUploadParams } = require('../utils/cloudinarySignature');

// Upload banner file (image or video) to Cloudinary
router.post('/upload', adminAuth, uploadBanner, async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
    }

    // Check if Cloudinary is configured
    if (!isConfigured || !cloudinary) {
        if (req.file && req.file.path) {
            deleteTempFile(req.file.path);
        }
        return res.status(500).json({ 
            message: 'Cloudinary is not configured. Please check your environment variables.' 
        });
    }

    try {
        // Detect file type from mimetype
        const mimetype = req.file.mimetype;
        const isImage = mimetype.startsWith('image/');
        const isVideo = mimetype.startsWith('video/');
        
        if (!isImage && !isVideo) {
            deleteTempFile(req.file.path);
            return res.status(400).json({ 
                message: 'Invalid file type. Only images and videos are allowed.' 
            });
        }

        const resourceType = isImage ? 'image' : 'video';
        const bannerType = isImage ? 'image' : 'video';

        // Get Cloudinary credentials
        const apiKey = process.env.CLOUDINARY_API_KEY;
        const apiSecret = process.env.CLOUDINARY_API_SECRET;

        if (!apiKey || !apiSecret) {
            deleteTempFile(req.file.path);
            return res.status(500).json({ 
                message: 'Cloudinary API credentials are missing. Please check your environment variables.' 
            });
        }

        // Build base upload options
        const baseOptions = {
            folder: 'banners',
            resource_type: resourceType,
            use_filename: true,
            unique_filename: true
        };

        // If upload preset is configured, use unsigned upload (no signature needed)
        if (process.env.CLOUDINARY_UPLOAD_PRESET) {
            baseOptions.upload_preset = process.env.CLOUDINARY_UPLOAD_PRESET;
            console.log('Using unsigned upload with preset:', process.env.CLOUDINARY_UPLOAD_PRESET);
            
            // Use standard upload method with preset (no signature needed)
            const result = await cloudinary.uploader.upload(req.file.path, baseOptions);
            const secureUrl = result.secure_url;

            // Delete temporary file
            deleteTempFile(req.file.path);

            // Save to MongoDB
            const banner = new Banner({
                title: req.body.title || 'Untitled Banner',
                description: req.body.description || '',
                image: secureUrl,
                banner_type: bannerType,
                link: req.body.link || '#',
                position: req.body.position || 'middle',
                size: req.body.size || 'medium',
                isActive: req.body.isActive !== undefined ? req.body.isActive : true
            });

            await banner.save();

            // Return JSON response
            return res.status(201).json({
                url: secureUrl,
                type: bannerType
            });
        }

        // For signed uploads, generate signature manually
        console.log('Using signed upload - generating signature...');
        
        // Prepare signed parameters
        const signedParams = prepareSignedUploadParams(baseOptions, apiKey, apiSecret);
        
        console.log('Uploading to Cloudinary with signed params:', {
            folder: signedParams.folder,
            resource_type: signedParams.resource_type,
            timestamp: signedParams.timestamp,
            api_key: signedParams.api_key ? '***' : undefined,
            signature: signedParams.signature ? signedParams.signature.substring(0, 8) + '...' : undefined
        });

        // IMPORTANT: When using manual signature, we need to temporarily remove api_secret from config
        // to prevent SDK from auto-generating signature, OR use the upload_stream method
        // The SDK will use our manual signature if we provide it
        
        // Use standard upload method with signed parameters
        // The SDK should use our provided signature instead of generating its own
        const result = await cloudinary.uploader.upload(req.file.path, {
            ...signedParams,
            // Explicitly set resource_type (required for videos)
            resource_type: resourceType
        });
        const secureUrl = result.secure_url;

        // Delete temporary file
        deleteTempFile(req.file.path);

        // Save to MongoDB
        const banner = new Banner({
            title: req.body.title || 'Untitled Banner',
            description: req.body.description || '',
            image: secureUrl,
            banner_type: bannerType,
            link: req.body.link || '#',
            position: req.body.position || 'middle',
            size: req.body.size || 'medium',
            isActive: req.body.isActive !== undefined ? req.body.isActive : true
        });

        await banner.save();

        // Return JSON response
        res.status(201).json({
            url: secureUrl,
            type: bannerType
        });
    } catch (error) {
        // Clean up temp file on error
        if (req.file && req.file.path) {
            deleteTempFile(req.file.path);
        }
        
        console.error('Banner upload error:', error);
        console.error('Error details:', {
            message: error.message,
            http_code: error.http_code,
            name: error.name
        });
        
        // Provide more helpful error messages
        let errorMessage = 'Failed to upload banner';
        if (error.message && error.message.includes('Invalid Signature')) {
            errorMessage = 'Cloudinary authentication error. Please check your CLOUDINARY_API_SECRET in environment variables.';
        } else if (error.message) {
            errorMessage = `Failed to upload banner: ${error.message}`;
        }
        
        res.status(500).json({ 
            message: errorMessage,
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

async function assignImageFields(target, body) {
    const providedUrl = body.image;
    if (providedUrl !== undefined) {
        target.image = providedUrl;
    }

    const fileId = body.imageFileId;
    if (fileId && fileId !== 'null' && fileId !== 'undefined') {
        const media = await Media.findById(fileId);
        if (!media) {
            const error = new Error('Invalid image file reference');
            error.statusCode = 400;
            throw error;
        }
        target.imageUpload = media._id;
        if (!target.image) {
            target.image = media.url;
        }
    } else if (fileId === '' || fileId === null) {
        target.imageUpload = undefined;
    }
}

// Get all active banners
router.get('/', async (req, res) => {
    try {
        const banners = await Banner.find({ isActive: true })
            .select('title description image imageUpload link position size isActive banner_type')
            .populate('imageUpload', 'url')
            .sort({ createdAt: -1 })
            .lean(); // Faster queries
        
        // Add aggressive cache headers
        res.set({
            'Cache-Control': 'public, max-age=300, s-maxage=600', // 5 min browser, 10 min CDN
            'Vary': 'Accept-Encoding'
        });
        res.json(banners);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Get banner by ID (public route for homepage sections)
router.get('/detail/:id', async (req, res) => {
    try {
        const banner = await Banner.findById(req.params.id).populate('imageUpload');
        if (!banner || !banner.isActive) {
            return res.status(404).json({ message: 'Banner not found' });
        }
        res.json(banner);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Get banner by position
router.get('/:position', async (req, res) => {
    try {
        const banner = await Banner.findOne({
            position: req.params.position,
            isActive: true
        }).populate('imageUpload');

        if (!banner) {
            return res.status(404).json({ message: 'Banner not found' });
        }
        res.json(banner);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Create a new banner (admin only)
router.post('/', adminAuth, async (req, res) => {
    const banner = new Banner({
        title: req.body.title,
        description: req.body.description,
        image: req.body.image,
        link: req.body.link,
        position: req.body.position || 'middle',
        size: req.body.size || 'medium',
        isActive: req.body.isActive !== undefined ? req.body.isActive : true
    });

    try {
        await assignImageFields(banner, req.body);
        const newBanner = await banner.save();
        const populatedBanner = await Banner.findById(newBanner._id).populate('imageUpload');
        res.status(201).json(populatedBanner);
    } catch (err) {
        const status = err.statusCode || 400;
        res.status(status).json({ message: err.message });
    }
});

// Update a banner (admin only)
router.put('/:id', adminAuth, async (req, res) => {
    try {
        const banner = await Banner.findById(req.params.id);
        if (!banner) {
            return res.status(404).json({ message: 'Banner not found' });
        }

        banner.title = req.body.title || banner.title;
        banner.description = req.body.description || banner.description;
        banner.link = req.body.link || banner.link;
        banner.position = req.body.position || banner.position;
        banner.size = req.body.size || banner.size || 'medium';
        banner.isActive = req.body.isActive !== undefined ? req.body.isActive : banner.isActive;

        await assignImageFields(banner, req.body);

        await banner.save();
        const populatedBanner = await Banner.findById(banner._id).populate('imageUpload');

        // Note: Banner position updates are now handled via HomepageSection model
        // Top banners can be manually added to homepage sections in admin dashboard

        res.json(populatedBanner);
    } catch (err) {
        const status = err.statusCode || 400;
        res.status(status).json({ message: err.message });
    }
});

// Delete a banner (admin only)
router.delete('/:id', adminAuth, async (req, res) => {
    try {
        const banner = await Banner.findById(req.params.id);
        if (!banner) {
            return res.status(404).json({ message: 'Banner not found' });
        }

        const position = banner.position;
        const image = banner.image;

        // Actually delete the banner from database
        await banner.deleteOne();

        // Note: Banner position updates are now handled via HomepageSection model
        // Top banners can be manually managed in homepage sections in admin dashboard

        res.json({ message: 'Banner deleted successfully' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

module.exports = router;