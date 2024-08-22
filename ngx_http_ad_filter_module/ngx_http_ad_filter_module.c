
/*
 * Copyright (C) Derek Sunder
 *  ____                _      ____                  _
 * |  _ \  ___ _ __ ___| | __ / ___| _   _ _ __   __| | ___ _ __
 * | | | |/ _ \ '__/ _ \ |/ / \___ \| | | | '_ \ / _` |/ _ \ '__|
 * | |_| |  __/ | |  __/   <   ___) | |_| | | | | (_| |  __/ |
 * |____/ \___|_|  \___|_|\_\ |____/ \__,_|_| |_|\__,_|\___|_|
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
	ngx_int_t            	ad_switch;
	ngx_str_t				ad_replace;
	ngx_str_t				ad_content;
} ngx_http_ad_loc_conf_t;


typedef struct {
	ngx_int_t				interrupt;
} ngx_http_ad_ctx_t;

static ngx_int_t ngx_http_ad_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_ad_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static void *ngx_http_ad_create_loc_conf(ngx_conf_t *cf);
//static char *ngx_http_ad_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_ad_init(ngx_conf_t *cf);

static ngx_command_t ngx_http_ad_filter_commands[] = {

    { ngx_string("ad_switch"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	  ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ad_loc_conf_t, ad_switch),
      NULL },

	{ ngx_string("ad_replace"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_ad_loc_conf_t, ad_replace),
	  NULL },

	{ ngx_string("ad_content"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
	  ngx_conf_set_str_slot,
	  //ngx_http_ad_content,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_ad_loc_conf_t, ad_content),
	  NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ad_filter_module_ctx = {
    NULL,          								/* preconfiguration */
    ngx_http_ad_init,                   		/* postconfiguration */

    NULL,                                  		/* create main configuration */
    NULL,                                  		/* init main configuration */

    NULL,                                  		/* create server configuration */
    NULL,                                  		/* merge server configuration */

    ngx_http_ad_create_loc_conf,        		/* create location configuration */
    NULL						          		/* merge location configuration */
};


ngx_module_t  ngx_http_ad_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_ad_filter_module_ctx,     	/* module context */
    ngx_http_ad_filter_commands,        	/* module directives */
    NGX_HTTP_MODULE,                       	/* module type */
    NULL,                                  	/* init master */
    NULL,                                  	/* init module */
    NULL,                                  	/* init process */
    NULL,                                  	/* init thread */
    NULL,                                  	/* exit thread */
    NULL,                                  	/* exit process */
    NULL,                                  	/* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_ad_header_filter(ngx_http_request_t *r)
{
    ngx_int_t                        	rc;
    ngx_http_ad_loc_conf_t       		*acf;
    ngx_http_headers_out_t 				*headers_out;
    ngx_table_elt_t						*h;
    ngx_http_ad_ctx_t					*ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ad_filter_module);
    if (ctx == NULL) {
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ad_ctx_t));
		if (ctx == NULL) {
			return NGX_ERROR;
		}
		ngx_http_set_ctx(r, ctx, ngx_http_ad_filter_module);
	}

    acf = ngx_http_get_module_loc_conf(r, ngx_http_ad_filter_module);
    headers_out = &r->headers_out;

    //输出头信息
    h = ngx_list_push(&headers_out->headers);
    if (h == NULL) {
    	return NGX_ERROR;
    }
    if (acf->ad_switch != 1) {			//swith off, keep next filtering
		return ngx_http_next_header_filter(r);
	} else {
		ngx_str_set(&h->key, "Ad-Filter");
		ngx_str_set(&h->value, "on");
	}
    h->hash = 1;		//if neet hash process
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = -1;
    r->chunked = 1;			//should set right content-length here, if not the content will be splited

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "header_print");

    rc = ngx_http_next_header_filter(r);
    return rc;
}

static ngx_int_t
ngx_http_ad_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	ngx_int_t                   		rc;
	ngx_buf_t							*buf;
	ngx_chain_t 						*cl, *out, *last;
	ngx_http_ad_ctx_t					*ctx;
	ngx_http_ad_loc_conf_t       		*adcf;

	out = NULL;
	last = NULL;
	ctx = ngx_http_get_module_ctx(r, ngx_http_ad_filter_module);
	if (ctx == NULL) {
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ad_ctx_t));
		if (ctx == NULL) {
			return NGX_ERROR;
		}
		ngx_http_set_ctx(r, ctx, ngx_http_ad_filter_module);
	}

	adcf = ngx_http_get_module_loc_conf(r, ngx_http_ad_filter_module);
	if (adcf->ad_switch <= 0) {			//ad switch off, keep next filtering
		return ngx_http_next_body_filter(r, in);
	}
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "replace: %s, content: %s", adcf->ad_replace.data, adcf->ad_content.data);
	if (adcf->ad_replace.len == 0 || adcf->ad_content.len == 0) {
		return ngx_http_next_body_filter(r, in);
	}

	for (cl = in; cl; cl = cl->next) {
		buf = cl->buf;

		if (buf->in_file) {
		    off_t file_offset = buf->file_pos;
		    off_t file_size = buf->file_last - buf->file_pos;

		    u_char *file_data = ngx_palloc(r->pool, file_size);
		    if (file_data == NULL) {
		    	ngx_pfree(r->pool, file_data);
		    	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "allocate file_data error");
		    	return ngx_http_next_body_filter(r, in);
		    }

		    ngx_file_t *file = buf->file;
		    ssize_t n = ngx_read_file(file, file_data, file_size, file_offset);
		    if (n == NGX_ERROR || (off_t)n != file_size) {
		    	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "read file error");
		    	ngx_pfree(r->pool, file_data);
		    	return ngx_http_next_body_filter(r, in);
		    }

		    //find ad_replace in file_data
		    u_char *pos;
			while ((pos = ngx_strnstr(file_data, (char *)adcf->ad_replace.data, file_size)) != NULL) {
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "pos: %s", pos);
				size_t prefix_len = pos - file_data;
				size_t suffix_len = file_size - (prefix_len + adcf->ad_replace.len);
				size_t new_len = prefix_len + adcf->ad_content.len + suffix_len;

				u_char *new_buf = ngx_palloc(r->pool, new_len);
				if (new_buf == NULL) {
					ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "allocate new_buf error");
					ngx_pfree(r->pool, new_buf);
					ngx_pfree(r->pool, file_data);
					return ngx_http_next_body_filter(r, in);
				}

				ngx_memcpy(new_buf, file_data, prefix_len);
				ngx_memcpy(new_buf + prefix_len, adcf->ad_content.data, adcf->ad_content.len);
				ngx_memcpy(new_buf + prefix_len + adcf->ad_content.len, pos + adcf->ad_replace.len, suffix_len);

				ngx_pfree(r->pool, file_data);
				file_data = new_buf;
				file_size = new_len;
			}

			buf->pos = file_data;
			buf->last = file_data + file_size;
			buf->memory = 1;
			buf->in_file = 0;
			buf->sync = 1;
			buf->last_buf = (cl->next == NULL);
			buf->flush = 1;

			ngx_chain_t *new_cl = ngx_alloc_chain_link(r->pool);
			if (new_cl == NULL) {
				return NGX_ERROR;
			}
			new_cl->buf = buf;
			new_cl->next = NULL;
			if (last == NULL) {
				out = new_cl;
			} else {
				last->next = new_cl;
			}

			last = new_cl;
		} else if (ngx_buf_in_memory(buf)) {
			if (buf->pos == NULL || buf->last == NULL || ngx_strlen(buf->pos) == 0 || ngx_strlen(buf->last) == 0 || buf->pos == buf->last) {
			    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "buffer is empty or not initialized correctly");
			    return ngx_http_next_body_filter(r, in);
			}
			while (1) {
				u_char *pos = ngx_strnstr(buf->pos, (char *)adcf->ad_replace.data, buf->last - buf->pos);
				if (pos == NULL)
					break;
				if (pos) {
					size_t prefix_len = pos - buf->pos;
					size_t suffix_len = buf->last - (pos + adcf->ad_replace.len);
					size_t new_len = prefix_len + adcf->ad_content.len + suffix_len;

					u_char *new_buf = ngx_palloc(r->pool, new_len);
					if (new_buf == NULL) {
						ngx_pfree(r->pool, new_buf);
						return ngx_http_next_body_filter(r, in);
					}

					ngx_memcpy(new_buf, buf->pos, prefix_len);
					ngx_memcpy(new_buf + prefix_len, adcf->ad_content.data, adcf->ad_content.len);
					ngx_memcpy(new_buf + prefix_len + adcf->ad_content.len, pos + adcf->ad_replace.len, suffix_len);

					buf->pos = new_buf;
					buf->last = new_buf + new_len;
					buf->flush = 1;
					buf->last_buf = (cl->next == NULL);
				} else {
					break;
				}
			}
			ngx_chain_t *new_cl = ngx_alloc_chain_link(r->pool);
			if (new_cl == NULL) {
				return NGX_ERROR;
			}
			new_cl->buf = buf;
			new_cl->next = NULL;

			if (last == NULL) {
				out = new_cl;
			} else {
				last->next = new_cl;
			}

			last = new_cl;
		}
	}

	rc = ngx_http_next_body_filter(r, out);
	if (rc == NGX_ERROR) {
	    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error in next body filter");
	    return NGX_ERROR;
	}
	return rc;
}

static void *
ngx_http_ad_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ad_loc_conf_t  *acf;

    acf = ngx_palloc(cf->pool, sizeof(ngx_http_ad_loc_conf_t));
    if (acf == NULL) {
        return NULL;
    }

    acf->ad_switch = NGX_CONF_UNSET;
    ngx_str_null(&acf->ad_replace);
    ngx_str_null(&acf->ad_content);

    return acf;
}

static ngx_int_t
ngx_http_ad_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ad_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_ad_body_filter;

    return NGX_OK;
}
