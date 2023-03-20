//
//  png_buffer.hpp
//  qrterm
//
//  Created by John Othwolo on 3/2/23.
//  Copyright © 2023 John Othwolo. All rights reserved.
//

#ifndef png_buffer_hpp
#define png_buffer_hpp

#include <sstream>
#include <fstream>

static void get_load_png_rw_callback(png_structp png_ptr, png_byte* outBytes, png_size_t byteCountToRead) {
    png_voidp io_ptr = png_get_io_ptr(png_ptr);
    if(io_ptr == NULL){
        fprintf(stderr, "get_load_png_rw_callback(): png_get_io_ptr() returned null");
        return;   // add custom error handling here
    }
    
    // -> replace with your own data source interface
    
    struct ReadInfo {
        std::vector<unsigned char> *imageData;
        size_t offset;
    } *info = (struct ReadInfo *)io_ptr;

    char *dataptr = ((char*)info->imageData->data()) + info->offset;
    
    memcpy(outBytes, dataptr, byteCountToRead);
    info->offset += byteCountToRead;
    
//    stream->read((char*)outBytes, byteCountToRead);

//    if((png_size_t)bytesRead != byteCountToRead){
//        fprintf(stderr, "didn't complete read");
//        return;   // add custom error handling here
//    }
}

/////////////////////////////////////////////////////////////////
//
//    Define main CImg plugin functions.
//    (you should use these functions only in your own code)
//
/////////////////////////////////////////////////////////////////

//! Load image from a png-coded memory buffer.
/**
   \param stream stream containing the png-file data.
   \param bits_per_value bits per value.
**/
static CImg get_load_png_stream(std::vector<unsigned char> *imageData, unsigned int *const bits_per_value=0) {
    // Setup PNG structures for read
    png_voidp user_error_ptr = 0;
    png_error_ptr user_error_fn = 0, user_warning_fn = 0;
    
    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING,user_error_ptr,user_error_fn,user_warning_fn);
    if (!png_ptr) {
        throw CImgIOException(_cimg_instance "load_png(): Failed to initialize 'png_ptr' structure with data.");
    }

    struct ReadInfo {
        std::vector<unsigned char> *imageData;
        size_t offset;
    } info = { imageData, 0 };
    
    // set read function
    png_set_read_fn(png_ptr, (png_bytep)&info, get_load_png_rw_callback);
    
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr,(png_infopp)0,(png_infopp)0);
        throw CImgIOException(_cimg_instance "load_png(): Failed to initialize 'info_ptr' structure for data.");
    }
    
    png_infop end_info = png_create_info_struct(png_ptr);
    if (!end_info) {
        png_destroy_read_struct(&png_ptr,&info_ptr,(png_infopp)0);
        throw CImgIOException(_cimg_instance "load_png(): Failed to initialize 'end_info' structure for data.");
    }
    
    // Error handling callback for png file reading
    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &end_info, (png_infopp)0);
        throw CImgIOException(_cimg_instance "load_png(): Encountered unknown fatal error in libpng for data.");
    }
                              
    // tell libpng we already read the signature
//    png_set_sig_bytes(png_ptr, 8);
    png_set_sig_bytes(png_ptr, 0);
    // print file size
    fprintf(stdout, "get_load_png_rw_callback(); size of file is %lu Bytes\n", imageData->size());
    
    // Get PNG Header Info up to data block
    png_read_info(png_ptr,info_ptr);
    png_uint_32 W, H;
    int bit_depth, color_type, interlace_type;
    bool is_gray = false;
    png_get_IHDR(png_ptr,info_ptr,&W,&H,&bit_depth,&color_type,&interlace_type,(int*)0,(int*)0);
    png_set_interlace_handling(png_ptr);
    if (bits_per_value) *bits_per_value = (unsigned int)bit_depth;
    
    // Transforms to unify image data
    if (color_type==PNG_COLOR_TYPE_PALETTE) {
        png_set_palette_to_rgb(png_ptr);
        color_type = PNG_COLOR_TYPE_RGB;
        bit_depth = 8;
    }
    if (color_type==PNG_COLOR_TYPE_GRAY && bit_depth<8) {
        png_set_expand_gray_1_2_4_to_8(png_ptr);
        is_gray = true;
        bit_depth = 8;
    }
    if (png_get_valid(png_ptr,info_ptr,PNG_INFO_tRNS)) {
        png_set_tRNS_to_alpha(png_ptr);
        color_type |= PNG_COLOR_MASK_ALPHA;
    }
    if (color_type==PNG_COLOR_TYPE_GRAY || color_type==PNG_COLOR_TYPE_GRAY_ALPHA) {
        png_set_gray_to_rgb(png_ptr);
        color_type |= PNG_COLOR_MASK_COLOR;
        is_gray = true;
    }
    if (color_type==PNG_COLOR_TYPE_RGB)
        png_set_filler(png_ptr,0xffffU,PNG_FILLER_AFTER);
    
    png_read_update_info(png_ptr,info_ptr);
    if (bit_depth!=8 && bit_depth!=16) {
        png_destroy_read_struct(&png_ptr,&end_info,(png_infopp)0);
        throw CImgIOException(_cimg_instance "load_png(): Invalid bit depth %u in data");
    }
    const int byte_depth = bit_depth>>3;
    
    // Allocate memory for image reading
    png_bytep *const imgData = new png_bytep[H];
    for (unsigned int row = 0; row<H; ++row) imgData[row] = new png_byte[(size_t)byte_depth*4*W];
    png_read_image(png_ptr,imgData);
    png_read_end(png_ptr,end_info);
    
    // Read pixel data
    if (color_type!=PNG_COLOR_TYPE_RGB && color_type!=PNG_COLOR_TYPE_RGB_ALPHA) {
        png_destroy_read_struct(&png_ptr,&end_info,(png_infopp)0);
        throw CImgIOException(_cimg_instance "load_png(): Invalid color coding type %u in data");
    }
    const bool is_alpha = (color_type==PNG_COLOR_TYPE_RGBA);
    
    CImg<T> dest(png_get_image_height(png_ptr,info_ptr), png_get_image_width(png_ptr,info_ptr), 1, 0);
    
    try { dest.assign(W,H,1,(is_gray?1:3) + (is_alpha?1:0)); }
    catch (...) { throw; }
    T
    *ptr_r = dest.data(0,0,0,0),
    *ptr_g = is_gray ? 0 : dest.data(0,0,0,1),
    *ptr_b = is_gray ? 0 : dest.data(0,0,0,2),
    *ptr_a = !is_alpha ? 0 : dest.data(0,0,0,is_gray?1:3);
    switch (bit_depth) {
        case 8 : {
            cimg_forY(dest,y) {
                const unsigned char *ptrs = (unsigned char*)imgData[y];
                cimg_forX(dest,x) {
                    *(ptr_r++) = (T)*(ptrs++);
                    if (ptr_g) *(ptr_g++) = (T)*(ptrs++); else ++ptrs;
                    if (ptr_b) *(ptr_b++) = (T)*(ptrs++); else ++ptrs;
                    if (ptr_a) *(ptr_a++) = (T)*(ptrs++); else ++ptrs;
                }
            }
        } break;
        case 16 : {
            cimg_forY(dest,y) {
                const unsigned short *ptrs = (unsigned short*)(imgData[y]);
                if (!cimg::endianness()) cimg::invert_endianness(ptrs,4*dest._width);
                cimg_forX(dest,x) {
                    *(ptr_r++) = (T)*(ptrs++);
                    if (ptr_g) *(ptr_g++) = (T)*(ptrs++); else ++ptrs;
                    if (ptr_b) *(ptr_b++) = (T)*(ptrs++); else ++ptrs;
                    if (ptr_a) *(ptr_a++) = (T)*(ptrs++); else ++ptrs;
                }
            }
        } break;
    }
    png_destroy_read_struct(&png_ptr, &info_ptr, &end_info);
    
    // Deallocate image read memory
    cimg_forY(dest,n) delete[] imgData[n];
    delete[] imgData;
    return dest;
}

//! Load image from a jpeg-coded memory buffer (in-place version)
/**
 \param stream stream containing the png-file data.
 \param bits_per_value bits per value.
**/
CImg& load_png_stream(std::vector<unsigned char> *stream, unsigned int *const bits_per_value=0) {
  return get_load_png_stream(stream, bits_per_value).move_to(*this);
}


#endif /* png_buffer_hpp */
