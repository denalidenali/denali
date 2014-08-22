#ifndef _LINK_LIST_H_
#define _LINK_LIST_H_
int beg_add_element(node **p_head, u_char *blob, int blob_size);
int end_add_element(node **p_head, u_char * blob, int blob_size);
int print_list(node *p_head);
int beg_del_element(node **p_head, u_char** fetch_data, u_int16_t *fetch_data_len, u_char** hmac_zip_data);
#endif /*_LINK_LIST_H_*/
