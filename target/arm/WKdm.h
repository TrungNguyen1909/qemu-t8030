#ifndef WKDM_H
#define WKDM_H

unsigned int WKdm_compress(void *src_buf,
                           void *dest_buf,
                           unsigned int size);

bool WKdm_decompress(void *src_buf,
                     void *dest_buf,
                     unsigned int size);
#endif /* WKDM_H */
