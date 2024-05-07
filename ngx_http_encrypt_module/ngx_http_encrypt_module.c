
/*
 * Copyright (C) Derek Sunder
 */
#include <ngx_md5.h>
#include <ngx_string.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>

//----------------------------------------------for AES--------------------------------------------------
#define BLOCKSIZE 16

typedef struct{
    uint32_t eK[44], dK[44];    // encKey, decKey
    int Nr; // 10 rounds
} AesKey;

#define LOAD32H(x, y) \
  do { (x) = ((uint32_t)((y)[0] & 0xff)<<24) | ((uint32_t)((y)[1] & 0xff)<<16) | \
             ((uint32_t)((y)[2] & 0xff)<<8)  | ((uint32_t)((y)[3] & 0xff));} while(0)

#define STORE32H(x, y) \
  do { (y)[0] = (uint8_t)(((x)>>24) & 0xff); (y)[1] = (uint8_t)(((x)>>16) & 0xff);   \
       (y)[2] = (uint8_t)(((x)>>8) & 0xff); (y)[3] = (uint8_t)((x) & 0xff); } while(0)

/* extract a byte */
#define BYTE(x, n) (((x) >> (8 * (n))) & 0xff)

/* used for keyExpansion */
#define MIX(x) (((S[BYTE(x, 2)] << 24) & 0xff000000) ^ ((S[BYTE(x, 1)] << 16) & 0xff0000) ^ \
                ((S[BYTE(x, 0)] << 8) & 0xff00) ^ (S[BYTE(x, 3)] & 0xff))

#define ROF32(x, n)  (((x) << (n)) | ((x) >> (32-(n))))

#define ROR32(x, n)  (((x) >> (n)) | ((x) << (32-(n))))

//-------------------------------------------------------------------------------------------------------

typedef struct {
	ngx_int_t            	encrypt_switch;
	ngx_str_t				encrypt_type;
	ngx_str_t			 	encrypt_key;
	ngx_array_t				*encrypt_param;
} ngx_http_encrypt_loc_conf_t;


typedef struct {
	ngx_int_t				interrupt;
} ngx_http_encrypt_ctx_t;

static ngx_int_t ngx_http_encrypt_header(ngx_http_request_t *r);
static void *ngx_http_encrypt_create_loc_conf(ngx_conf_t *cf);
//static char *ngx_http_encrypt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_encrypt_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_encrypt_combine_params(ngx_array_t *requires, ngx_log_t *log, char *content, ngx_http_headers_in_t *headers_in);
static char *ngx_http_encrypt_param(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
int ngx_http_encrypt_content(ngx_str_t encrypt_type, ngx_str_t encrypt_key, char *content, char **result, ngx_http_request_t *r);
//-------------------------------------------------------------------------------------------------------

//--------------------------------------------------for AES----------------------------------------------
int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                 const unsigned char *key, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL))
        return -1;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
//-------------------------------------------------------------------------------------------------------


static ngx_command_t ngx_http_encrypt_commands[] = {

    { ngx_string("encrypt_switch"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	  ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_encrypt_loc_conf_t, encrypt_switch),
      NULL },

    { ngx_string("encrypt_type"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_encrypt_loc_conf_t, encrypt_type),
	  NULL },

	{ ngx_string("encrypt_key"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_encrypt_loc_conf_t, encrypt_key),
	  NULL },

	{ ngx_string("encrypt_param"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
//	  ngx_conf_set_str_array_slot,
	  ngx_http_encrypt_param,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_encrypt_loc_conf_t, encrypt_param),
	  NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_encrypt_module_ctx = {
    NULL,          								/* preconfiguration */
    ngx_http_encrypt_init,                   	/* postconfiguration */

    NULL,                                  		/* create main configuration */
    NULL,                                  		/* init main configuration */

    NULL,                                  		/* create server configuration */
    NULL,                                  		/* merge server configuration */

    ngx_http_encrypt_create_loc_conf,        	/* create location configuration */
    NULL						          		/* merge location configuration */
};


ngx_module_t  ngx_http_encrypt_module = {
    NGX_MODULE_V1,
    &ngx_http_encrypt_module_ctx,     	   /* module context */
    ngx_http_encrypt_commands,        	   /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_encrypt_header(ngx_http_request_t *r)
{
    ngx_int_t                        	rc;
    ngx_http_encrypt_loc_conf_t       	*slcf;
    ngx_http_headers_in_t 				*headers_in;
    ngx_http_headers_out_t 				*headers_out;
    ngx_table_elt_t						*h;
    ngx_http_encrypt_ctx_t				*ctx;
    ngx_chain_t  						out;
    ngx_buf_t   						*b;
    ngx_uint_t 							i;
    ngx_str_t 							src, dst;
    int content_length = 0;
    int len = 512;

    u_char sign_key[] = "sign";
    u_char sign_val[256] = {0};

    ctx = ngx_http_get_module_ctx(r, ngx_http_encrypt_module);
    if (ctx == NULL) {
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_encrypt_ctx_t));
		if (ctx == NULL) {
			return NGX_ERROR;
		}
		ngx_http_set_ctx(r, ctx, ngx_http_encrypt_module);
	}

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_encrypt_module);
    headers_in = &r->headers_in;
    headers_out = &r->headers_out;
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "encrypt_switch:=%d", slcf->encrypt_switch);

    if (slcf->encrypt_switch <= 0) {			//swith off, keep next filtering
    	return NGX_OK;
    }

//    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "siwtch:%d, type:%s, key:%s", slcf->encrypt_switch, slcf->encrypt_key.data, slcf->encrypt_type.data, slcf->encrypt_key.data);
    //遍历list打印一下
    /*ngx_list_part_t *part = &headers_in->headers.part;
    ngx_table_elt_t *data = part->elts;
    ngx_uint_t i;
    for (i = 0; ; i++) {
    	if (i >= part->nelts) {
    		if (part->next == NULL)
    			break;
    		part = part->next;
    		data = part->elts;
    		i = 0;
    	}
    	ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "header_data:%V:%V", &data[i].key, &data[i].value);
    }*/

    char content[2048] = {0};
    ngx_http_encrypt_combine_params(slcf->encrypt_param, r->connection->log, content, headers_in);
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "content:%s", content);
    //去加密
    char *result = (char *)malloc(sizeof(char)*2);
    ngx_memset(result, 0, 2);
    int res = ngx_http_encrypt_content(slcf->encrypt_type, slcf->encrypt_key, content, &result, r);
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "result===:%s, len=%d, res=%d", result, strlen(result), res);
    //判断是否加密类型是md5/AES
    if (res == -1) {
    	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    src.len = strlen(result);
	src.data = (u_char *) result;
	dst.len = ngx_base64_encoded_length(src.len);
	len = dst.len;
	dst.data = ngx_palloc(r->pool, len);
	if (dst.data == NULL) {
		return NGX_ERROR;
	}
    ngx_encode_base64(&dst, &src);
    char base_res[len+1];
    ngx_memcpy(base_res, dst.data, dst.len);
    base_res[len] = '\0';
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "dst.data:=%s, len:=%d, base_res:=%s, base_res_len:=%d", dst.data, dst.len, base_res, strlen(base_res));

//    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
//                   "encrypt: %d, %s, %s", slcf->encrypt_switch, slcf->encrypt_type.data, slcf->encrypt_key.data);

    //输出头信息
    h = ngx_list_push(&headers_out->headers);
    if (h == NULL) {
    	return NGX_ERROR;
    }
    h->hash = 1;		//if neet hash process

    //比较请求的加密串和服务器加密结果
    ngx_list_part_t *hpart = &headers_in->headers.part;
    ngx_table_elt_t *hdata = hpart->elts;
    for (i = 0; ; i++) {
		if (i >= hpart->nelts) {
			if (hpart->next == NULL)
				break;
			hpart = hpart->next;
			hdata = hpart->elts;
			i = 0;
		}
		if (ngx_strcasecmp(hdata[i].key.data, sign_key) == 0) {
			memcpy(sign_val, hdata[i].value.data, hdata[i].value.len + 1);
			break;
		}
    }
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "sign_val:%s, len:=%d", sign_val, strlen((char *)sign_val));
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "compare:=%d", ngx_strcasecmp(sign_val, (u_char *)base_res));

    if (strlen((char *)sign_val) == 0) {
    	ngx_str_set(&h->key, "Auth-Result");
		ngx_str_set(&h->value, "param_error");
		r->headers_out.status = NGX_HTTP_UNAUTHORIZED;
		ctx->interrupt = 1;
    } else {
		if (ngx_strcasecmp(sign_val, (u_char *)base_res) == 0) {
			ngx_str_set(&h->key, "Auth-Result");
			ngx_str_set(&h->value, "excellent");
			r->headers_out.status = NGX_HTTP_OK;
			ctx->interrupt = 0;
		} else {
			ngx_str_set(&h->key, "Auth-Result");
			ngx_str_set(&h->value, "unfaith");
			r->headers_out.status = NGX_HTTP_UNAUTHORIZED;
			ctx->interrupt = 1;
		}
    }
    free(result);

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "interrupt:=%d", ctx->interrupt);
    if (ctx->interrupt == 1) {
    	u_char ngx_warn_string[14] = "encrypt error!";
    	content_length = 14;
    	ngx_str_set(&r->headers_out.content_type, "text/html");
    	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
		if (b == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		out.buf = b;
		out.next = NULL;
		b->pos = ngx_warn_string;
		b->last = ngx_warn_string + content_length;
		b->memory = 1;    /* this buffer is in memory */
		b->last_buf = 1;
		//r->headers_out.status = NGX_HTTP_OK;
		r->headers_out.content_length_n = content_length;
		rc = ngx_http_send_header(r);

		//return NGX_HTTP_FORBIDDEN;		//can return 403 directly

		if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
			return rc;
		}
		return ngx_http_output_filter(r, &out);
    }
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "run this way!");
    return NGX_OK;
}

/**
 * 加密
 */
int ngx_http_encrypt_content(ngx_str_t encrypt_type, ngx_str_t encrypt_key, char *content, char **result, ngx_http_request_t *r) {
	u_char md5[] = "md5";
	u_char aes[] = "aes";
	int compare_res = -1;
	if (ngx_strcasecmp(encrypt_type.data, md5) == 0) {
		ngx_md5_t md5;
		ngx_md5_init(&md5);
		unsigned char decrypt[16];
		char sub[encrypt_key.len + 1];
		int i;
		sprintf(sub, "&%s", encrypt_key.data);
		strcat(content, sub);
		*result = realloc(*result, sizeof(char) * 33);
		ngx_md5_update(&md5, (unsigned char *)content, strlen(content));
		ngx_md5_final(decrypt, &md5);
		for(i = 0; i < 16; i++) {
			char *str = (char *)malloc(sizeof(char *) * 2);
			sprintf(str, "%02x", decrypt[i]);
			strcat(*result, str);
			free(str);
		}
		compare_res = 1;
	} else if (ngx_strcasecmp(encrypt_type.data, aes) == 0) {
		unsigned char key[33];
		unsigned char plaintext[strlen(content)];
		ngx_memcpy(key, encrypt_key.data, encrypt_key.len);
		key[encrypt_key.len] = '\0';
		ngx_memcpy(plaintext, content, strlen(content));
		plaintext[strlen(content)] = '\0';
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "aes_key:=%s, plaintext:=%s", key, plaintext);
		int plaintext_len = strlen((char *)plaintext);
		//encrypt(only support ecb here)
		*result = realloc(*result, sizeof(char) * 512);
		ngx_memset(*result, 0, 512);
		aes_encrypt(plaintext, plaintext_len, key, (unsigned char *)*result);
		compare_res = 1;
	} else {
		compare_res = -1;
		free(*result);
		ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "other_result:=%s", *result);
	}
	return compare_res;
}

static ngx_int_t ngx_http_encrypt_combine_params(ngx_array_t *requires, ngx_log_t *log, char *content, ngx_http_headers_in_t *headers_in)
{
    ngx_str_t   *script;
    ngx_uint_t   i, j;
    ngx_list_part_t *part = &headers_in->headers.part;
    ngx_table_elt_t *data = part->elts;
    char *delimeter = "&";

    if (requires == NGX_CONF_UNSET_PTR) {
        return NGX_OK;
    }

    script = requires->elts;
    for (i = 0; i < requires->nelts; i++) {
    	ngx_uint_t empty = 0;
		for (j = 0; ; j++) {
			if (j >= part->nelts) {
				if (part->next == NULL)
					break;
				part = part->next;
				data = part->elts;
				j = 0;
			}
			//ngx_log_error(NGX_LOG_EMERG, log, 0,  "j=%d, part=%d", j, part->nelts);
			//ngx_log_error(NGX_LOG_EMERG, log, 0,  "=========%s, %s, compare=%d", data[j].key.data, script[i].data, ngx_strcasecmp(data[j].key.data, script[i].data));
			if (ngx_strcasecmp(data[j].key.data, script[i].data) == 0) {
				u_char sub[100] = {0};
				if (strlen(content) == 0) {
					ngx_sprintf(sub, "%s=%s", script[i].data, data[j].value.data);
				} else {
					ngx_sprintf(sub, "%s%s=%s", delimeter, script[i].data, data[j].value.data);
				}
				strcat(content, (char *)sub);
				break;
			} else {
				empty++;
			}
			//ngx_log_error(NGX_LOG_EMERG, log, 0,  "empty=%d", empty);
			if (empty == part->nelts) {
				u_char sub[100] = {0};
				if (strlen(content) == 0) {
					ngx_sprintf(sub, "%s=", script[i].data);
				} else {
					ngx_sprintf(sub, "%s%s=", delimeter, script[i].data);
				}
				strcat(content, (char *)sub);
			}
		}
	//ngx_log_error(NGX_LOG_EMERG, log, 0,  "param[%d]=%s", i, script[i].data);
    }
    return NGX_OK;
}

static void *
ngx_http_encrypt_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_encrypt_loc_conf_t  *slcf;

    slcf = ngx_palloc(cf->pool, sizeof(ngx_http_encrypt_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    slcf->encrypt_switch = NGX_CONF_UNSET;
    ngx_str_null(&slcf->encrypt_type);
    ngx_str_null(&slcf->encrypt_key);
    slcf->encrypt_param = NGX_CONF_UNSET_PTR;

    return slcf;
}

static char *ngx_http_encrypt_param(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_encrypt_loc_conf_t  *slcf = conf;

	ngx_str_t *value;
	ngx_uint_t i;

	slcf->encrypt_param = ngx_array_create(cf->pool, cf->args->nelts - 1, sizeof(ngx_str_t));
	if (slcf->encrypt_param == NULL) {
		return NGX_CONF_ERROR;
	}
	value = cf->args->elts;
	for (i = 1; i < cf->args->nelts; i++) {
		ngx_str_t *param = ngx_array_push(slcf->encrypt_param);
		if (param == NULL) {
			return NGX_CONF_ERROR;
		}
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "conf_param:[%d]=%s", i, value[i].data);
		*param = value[i];
	}

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_encrypt_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);		//NGX_HTTP_CONTENT_PHASE这个阶段handler中返回NGX_OK无效卡住，需要实际输出内容才行
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_encrypt_header;

	return NGX_OK;
}
